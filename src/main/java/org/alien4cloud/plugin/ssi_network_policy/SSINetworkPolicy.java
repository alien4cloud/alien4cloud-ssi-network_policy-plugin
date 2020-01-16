package org.alien4cloud.plugin.ssi_network_policy;

import alien4cloud.paas.wf.validation.WorkflowValidator;
import alien4cloud.tosca.context.ToscaContext;
import alien4cloud.tosca.context.ToscaContextual;
import static alien4cloud.utils.AlienUtils.safe;
import alien4cloud.utils.PropertyUtil;

import org.alien4cloud.alm.deployment.configuration.flow.FlowExecutionContext;
import org.alien4cloud.alm.deployment.configuration.flow.TopologyModifierSupport;
import org.alien4cloud.tosca.model.CSARDependency;
import org.alien4cloud.tosca.model.definitions.AbstractPropertyValue;
import org.alien4cloud.tosca.model.definitions.ScalarPropertyValue;
import org.alien4cloud.tosca.model.templates.Capability;
import org.alien4cloud.tosca.model.templates.NodeTemplate;
import org.alien4cloud.tosca.model.templates.PolicyTemplate;
import org.alien4cloud.tosca.model.templates.RelationshipTemplate;
import org.alien4cloud.tosca.model.templates.Requirement;
import org.alien4cloud.tosca.model.templates.Topology;
import org.alien4cloud.tosca.model.types.NodeType;
import org.alien4cloud.tosca.model.types.RelationshipType;
import org.alien4cloud.tosca.normative.constants.NormativeRelationshipConstants;
import org.alien4cloud.tosca.utils.IRelationshipTypeFinder;
import org.alien4cloud.tosca.utils.TopologyNavigationUtil;
import org.alien4cloud.tosca.utils.ToscaTypeUtils;

import static org.alien4cloud.plugin.consulpublisher.policies.ConsulPublisherPolicyConstants.CONSULPUBLISHER_POLICY1;
import static org.alien4cloud.plugin.consulpublisher.policies.ConsulPublisherPolicyConstants.CONSULPUBLISHER_POLICY2;
import static org.alien4cloud.plugin.kubernetes.csar.Version.K8S_CSAR_VERSION;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.A4C_KUBERNETES_ADAPTER_MODIFIER_TAG_REPLACEMENT_NODE_FOR;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.K8S_TYPES_KUBECONTAINER;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.K8S_TYPES_KUBE_CLUSTER;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.NAMESPACE_RESOURCE_NAME;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_DEPLOYMENT_RESOURCE;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_SIMPLE_RESOURCE;

import org.springframework.stereotype.Component;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Component("ssi-network_policy-modifier")
public class SSINetworkPolicy extends TopologyModifierSupport {

    private final ObjectMapper mapper = new ObjectMapper();

    private final String DATASTORE_RELATIONSHIP = "artemis.relationships.pub.ConnectsToDataStore";

    // known datastores
    private Map<String, ImmutablePair<String,String>> dataStoreTypes = Stream.of(new Object[][] { 
        //{ "artemis.redis.pub.capabilities.Redis", "redis", "redis_endpoint" }, 
        { "artemis.mongodb.pub.capabilities.MongoDb", "mongodb", "mongodb_endpoint" }, 
        { "artemis.mariadb.pub.capabilities.Mariadb", "mariadb", "mariadb_endpoint" }, 
        { "artemis.postgresql.pub.capabilities.PostgreSQLEndpoint", "postgre", "postgresql_endpoint" },
        { "artemis.accumulo.pub.capabilities.Accumulo", "accumulo", "accumulo_endpoint" },
        { "artemis.cassandra.pub.capabilities.CassandraDb", "cassandra", "cassandra_endpoint" },
        { "artemis.elasticsearch.pub.capabilities.ElasticSearchRestAPI", "elastic", "http" },
        { "artemis.kafka.pub.capabilities.KafkaTopic", "kafka", "kafka_topic" },
        { "artemis.hadoop.pub.capabilities.HdfsRepository", "hdfs", "hdfs_repository" },
        { "artemis.ceph.pub.capabilities.CephBucketEndpoint", "ceph", "http" }
    }).collect(Collectors.toMap(data -> (String) data[0], data -> new ImmutablePair<String,String>((String) data[1], (String) data[2])));

    @Override
    @ToscaContextual
    public void process(Topology topology, FlowExecutionContext context) {
        log.info("Processing topology " + topology.getId());

        try {
            WorkflowValidator.disableValidationThreadLocal.set(true);
            doProcess(topology, context);
        } catch (Exception e) {
            log.warn ("Couldn't process SSINetworkPolicy modifier, got " + e.getMessage());
            log.error("Exception ", e);
        } finally {
            WorkflowValidator.disableValidationThreadLocal.remove();
        }
    }

    private void doProcess(Topology topology, FlowExecutionContext context) {
       Set<NodeTemplate> kubeNodes = TopologyNavigationUtil.getNodesOfType(topology, K8S_TYPES_DEPLOYMENT_RESOURCE, true);

       /* get initial topology */
       Topology init_topology = (Topology)context.getExecutionCache().get(FlowExecutionContext.INITIAL_TOPOLOGY);

       Set<NodeTemplate> kubeClusterNodes = TopologyNavigationUtil.getNodesOfType(init_topology, K8S_TYPES_KUBE_CLUSTER, false);
       if ((kubeClusterNodes == null) || kubeClusterNodes.isEmpty()) {
          log.info("Not a kubernetes appli, nothing to do.");
          return;
       }

       /* get consul publisher policies */
       Set<PolicyTemplate> policiesIhm = TopologyNavigationUtil.getPoliciesOfType(init_topology, CONSULPUBLISHER_POLICY1, false);
       Set<PolicyTemplate> policiesApi = TopologyNavigationUtil.getPoliciesOfType(init_topology, CONSULPUBLISHER_POLICY2, false);

       /* keep kube config for network policies */
       AbstractPropertyValue configPV = null;

       boolean hasDs = false,
               hasIhm = false,
               hasApi = false;
       List<Integer> ihmPorts = new ArrayList<Integer>();
       List<Integer> apiPorts = new ArrayList<Integer>();
       Set<String> allDS = new HashSet<String>();

       /* process all kube deployment resources nodes */
       for (NodeTemplate node: safe(kubeNodes)) {
          log.info("Processing node " + node.getName());

          /* any kube config will do */
          configPV = node.getProperties().get("kube_config");
  
          boolean ihm = false,
                  api = false;
          Set<String> nodeDS = new HashSet<String>();

          /* look for node in initial topology */
          String initialNodeName  = TopologyModifierSupport.getNodeTagValueOrNull(node, A4C_KUBERNETES_ADAPTER_MODIFIER_TAG_REPLACEMENT_NODE_FOR);
          NodeTemplate initialNode = init_topology.getNodeTemplates().get(initialNodeName);

          if (initialNode == null) {
             log.warn ("Can not find initial node for " + node.getName());
          } else {
             nodeDS = usesDataStore (initialNode, init_topology);
             if (!nodeDS.isEmpty()) {
                log.info (node.getName() + " uses datastore(s).");
                hasDs = true;
                allDS.addAll(nodeDS);
             }
             Integer port = exposes(initialNode, init_topology, policiesIhm);
             if (port.intValue() != -1) {
                log.info (node.getName() + " exposes IHM.");
                ihm = true;
                hasIhm = true;
                ihmPorts.add(port);
             }
             port = exposes(initialNode, init_topology, policiesApi);
             if (port.intValue() != -1) {
                log.info (node.getName() + " exposes API.");
                api = true;
                hasApi = true;
                apiPorts.add(port);
             }
          }

          ScalarPropertyValue specProp = (ScalarPropertyValue) node.getProperties().get("resource_spec");
          try {
              ObjectNode spec = (ObjectNode) mapper.readTree(PropertyUtil.getScalarValue(specProp));

              addLabel (spec, "pod-pf-role", "module");
              addLabel (spec, "expose-ihm", Boolean.toString(ihm));
              addLabel (spec, "expose-api", Boolean.toString(api));
              for (String ds : nodeDS) {
                 addLabel (spec, ds, "true");
              }
              addLabel (spec, "access-iam", "false");

              specProp.setValue(mapper.writeValueAsString(spec));
          } catch(IOException e) {
              log.error("Can't parse json: {}",e);
          }
       }

       /* get info on namespace if any */
       String namespace = null,
              zds = null;
       NodeTemplate kubeNS = topology.getNodeTemplates().get((String)context.getExecutionCache().get(NAMESPACE_RESOURCE_NAME));
       if (kubeNS != null) {
          namespace = PropertyUtil.getScalarValue(kubeNS.getProperties().get("resource_id"));
          try {
              ObjectNode spec = (ObjectNode) mapper.readTree(PropertyUtil.getScalarValue(kubeNS.getProperties().get("resource_spec")));
              zds = spec.with("metadata").with("labels").get("ns-zone-de-sensibilite").textValue();
          } catch(Exception e) {
              log.info("Can't find ns-zone-de-sensibilite");
          }
       } else {
          log.info ("No namespace");
       }

       if ((namespace != null) && !namespace.trim().equals("") &&
           (zds != null) && !zds.trim().equals("") ) {
          generateNetworkPolicies (topology, namespace, zds, configPV, kubeNodes, 
                                   hasDs, allDS, hasIhm, hasApi, ihmPorts, apiPorts);
       }
    }

    /**
     * tests whether given node uses datastore(s) or not
     **/
    private Set<String> usesDataStore (NodeTemplate node, Topology init_topology) {
       Set<String> ds = new HashSet<String>();
       /**
        * input node is KubeDeployment
        * look for KubeContainer node hostedOn this node
        * look for relationship datastores on this KubeContainer node
        **/
       ToscaContext.Context toscaContext = new ToscaContext.Context(init_topology.getDependencies());
       Set<NodeTemplate> containerNodes = getNodesOfType(init_topology, K8S_TYPES_KUBECONTAINER, toscaContext);
       for (NodeTemplate containerNode : safe(containerNodes)) {
          NodeTemplate host = getImmediateHostTemplate(init_topology, containerNode, toscaContext);
          if (host == node) {
             Set<String> oneDs = hasDataStoreRelationship(init_topology, containerNode);
             if (!oneDs.isEmpty()) {
                ds.addAll(oneDs);
             }
          }
       }
       return ds;
    }

    /**
     * tests whether given node has relationship to datastore or not, 
     * if so return associated keyword
     **/
    private Set<String> hasDataStoreRelationship (Topology topology, NodeTemplate node) {
       Set<String> ds = new HashSet<String>();
       for (RelationshipTemplate relationshipTemplate : safe(node.getRelationships()).values()) {
          if (relationshipTemplate.getType().equals(DATASTORE_RELATIONSHIP)) {
             ImmutablePair<String,String> val = dataStoreTypes.get(relationshipTemplate.getRequirementType());
             
             if (val != null) {
                String access = val.getLeft();
                String capa = val.getRight();
                Capability endpoint = safe(topology.getNodeTemplates().get(relationshipTemplate.getTarget()).getCapabilities()).get(capa);
                String instname = "default";
                if (endpoint != null) {
                   instname = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("artemis_instance_name"));
                }

                ds.add("access-" + access + "--" + instname);
             }
          }
       }
       return ds;
    }

    /** 
     * tests whether given node uses given policy or not
     *  policy : target = service
     *  service : relationship connectsTo : container
     *  container : relationship hostedOn : deployment
     **/
    private Integer exposes (NodeTemplate node, Topology topology, Set<PolicyTemplate> policies) {
       for (PolicyTemplate policy : safe(policies)) {
          for (NodeTemplate service : TopologyNavigationUtil.getTargetedMembers(topology, policy)) {
             NodeTemplate container = getConnectsTo (topology, service);
             NodeTemplate deployment = TopologyNavigationUtil.getImmediateHostTemplate(topology, container);
             if (deployment == node) {
                return getPort(service);
             }
          }
       }
       return -1;
    }

    private Integer getPort (NodeTemplate service) {
       /* get port from capability properties of service */
       Integer port = new Integer(80);
       Capability endpoint = safe(service.getCapabilities()).get("service_endpoint");
       if (endpoint != null) {
          String sport = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("port"));
          if (StringUtils.isNotEmpty(sport)) {
             port = new Integer(sport);
          }
       }
       return port;
    }

    /**
     * get "connects to" relationship target node
     **/
    private NodeTemplate getConnectsTo (Topology topology, NodeTemplate node) {
        RelationshipTemplate target = TopologyNavigationUtil.getRelationshipFromType(node, NormativeRelationshipConstants.CONNECTS_TO);
        if (target == null) {
            return null;
        }
        return topology.getNodeTemplates().get(target.getTarget());
    }

    /**
     * add label to pod labels and matchLabels
     **/
    private void addLabel(ObjectNode spec,String key,String value) {
        spec.with("spec").with("template").with("metadata").with("labels").put(key,value);
        spec.with("spec").with("selector").with("matchLabels").put(key,value);
    }

    /**
     * generate all required network policies for namespace 
     **/
    private void generateNetworkPolicies (Topology topology, String namespace, String zds, AbstractPropertyValue configPV,
                                          Set<NodeTemplate> deployNodes, boolean ds, Set<String> allDS, boolean ihm, boolean api,
                                          List<Integer> ihmPorts, List<Integer> apiPorts) {
       String resource_spec = 
              "apiVersion: networking.k8s.io/v1\n" +
              "kind: NetworkPolicy\n" +
              "metadata:\n" +
              "  name: a4c-default-in-policy\n" +
              "  labels:\n" + 
              "    a4c_id: a4c-default-in-policy\n" + 
              "spec:\n" +
              "  podSelector: {}\n" +
              "  policyTypes:\n" +
              "  - Ingress\n" +
              "  ingress:\n" +
              "  - from:\n" +
              "    - namespaceSelector:\n" +
              "        matchLabels:\n" +
              "          ns-clef-namespace: " + namespace;
       generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_default_in_policy", "a4c-default-in-policy", configPV);

       resource_spec = 
              "apiVersion: networking.k8s.io/v1\n" +
              "kind: NetworkPolicy\n" +
              "metadata:\n" +
              "  name: a4c-default-eg-policy\n" +
              "  labels:\n" + 
              "    a4c_id: a4c-default-eg-policy\n" + 
              "spec:\n" +
              "  podSelector: {}\n" +
              "  policyTypes:\n" +
              "  - Egress\n" +
              "  egress:\n" +
              "  - to:\n" +
              "    - namespaceSelector:\n" +
              "        matchLabels:\n" +
              "          ns-clef-namespace: " + namespace;
       generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_default_eg_policy", "a4c-default-eg-policy", configPV);
       
       resource_spec = 
              "apiVersion: networking.k8s.io/v1\n" +
              "kind: NetworkPolicy\n" +
              "metadata:\n" +
              "  name: a4c-kube-system-policy\n" +
              "  labels:\n" +
              "    a4c_id: a4c-kube-system-policy\n" +
              "spec:\n" +
              "  podSelector: {}\n" +
              "  ingress:\n" +
              "  - from:\n" +
              "    - namespaceSelector:\n" +
              "        matchLabels:\n" +
              "          ns-clef-namespace: kube-system\n" +
              "  policyTypes:\n" +
              "  - Ingress\n";
       generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_kube_system_policy", "a4c-kube-system-policy", configPV);


       if (ds) {
          for (String oneDS : allDS) {
             String a4cds = oneDS.replaceAll("-","_");
             resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-" + oneDS + "-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-" + oneDS + "-policy\n" + 
                 "spec:\n" +
                 "  podSelector:\n" +
                 "    matchLabels:\n" +
                 "      " + oneDS + ": \"true\"\n" +
                 "  policyTypes:\n" +
                 "  - Egress\n" +
                 "  egress:\n" +
                 "  - to:\n" +
                 "    - namespaceSelector:\n" +
                 "        matchLabels:\n" +
                 "          ns-zone-de-sensibilite: " + zds + "\n" +
                 "          ns-pf-role: iad\n" +
                 "    - podSelector:\n" +
                 "        matchLabels:\n" +
                 "          pod-pf-role: iad\n"; 

             generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_" + a4cds + "_policy", "a4c-" + oneDS + "-policy", configPV);
          }
       }

       if (ihm) {
          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-ihm-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-ihm-policy\n" + 
                 "spec:\n" +
                 "  podSelector:\n" +
                 "    matchLabels:\n" +
                 "      expose-ihm: \"true\"\n" +
                 "  policyTypes:\n" +
                 "  - Ingress\n" +
                 "  ingress:\n" +
                 "  - from:\n" +
                 "    - namespaceSelector:\n" +
                 "        matchLabels:\n" +
                 "          ns-zone-de-sensibilite: " + zds + "\n" +
                 "          ns-pf-role: portail\n" +
                 "    - podSelector:\n" +
                 "       matchLabels:\n" +
                 "         pod-pf-role: rproxy\n" +
                 "    ports:\n";
          for (Integer port : ihmPorts) {
             resource_spec += "       - port: " + port.toString() + "\n";
          }

          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_ihm_policy", "a4c-ihm-policy", configPV);
       }

       if (api) {
          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-api-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-api-policy\n" + 
                 "spec:\n" +
                 "  podSelector:\n" +
                 "    matchLabels:\n" +
                 "      expose-api: \"true\"\n" +
                 "  policyTypes:\n" +
                 "  - Ingress\n" +
                 "  ingress:\n" +
                 "  - from:\n" +
                 "    - namespaceSelector:\n" +
                 "        matchLabels:\n" +
                 "          ns-zone-de-sensibilite: " + zds + "\n" +
                 "          ns-pf-role: portail\n" +
                 "    - podSelector:\n" +
                 "       matchLabels:\n" +
                 "         pod-pf-role: apigw\n"+
                 "    ports:\n";
          for (Integer port : apiPorts) {
             resource_spec += "       - port: " + port.toString() + "\n";
          }

          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_api_policy", "a4c-api-policy", configPV);
       }
    }

    /**
     * generate a network policies for namespace 
     **/
    private void generateOneNetworkPolicy (Topology topology, Set<NodeTemplate> deployNodes, String resource_spec, String policyNodeName,
                                           String policyName, AbstractPropertyValue configPV) {
       /* create SimpleResource with props resource_id, resource_type, resource_spec and kube_config */
       NodeTemplate polResourceNode = addNodeTemplate(null, topology, policyNodeName, K8S_TYPES_SIMPLE_RESOURCE, getK8SCsarVersion(topology));

       setNodePropertyPathValue(null, topology, polResourceNode, "resource_id", new ScalarPropertyValue(policyName));
       setNodePropertyPathValue(null, topology, polResourceNode, "resource_type", new ScalarPropertyValue("networkpolicy"));
       setNodePropertyPathValue(null, topology, polResourceNode, "kube_config", configPV);
       setNodePropertyPathValue(null, topology, polResourceNode, "resource_spec", new ScalarPropertyValue(resource_spec));

       /* add relations */
       for (NodeTemplate deploymentResourceNode : safe(deployNodes)) {
           addRelationshipTemplate (null,
                                    topology,
                                    polResourceNode,
                                    deploymentResourceNode.getName(),
                                    NormativeRelationshipConstants.DEPENDS_ON,
                                    "dependency",
                                    "feature");
       }
    }

    /**
     * get CSAT version from dependencies if any
     **/
    private String getK8SCsarVersion(Topology topology) {
        for (CSARDependency dep : topology.getDependencies()) {
            if (dep.getName().equals("org.alien4cloud.kubernetes.api")) {
                return dep.getVersion();
            }
        }
        return K8S_CSAR_VERSION;
    }

    /**
     * methods inspired by TopologyNavigationUtils, here we use a toscaContext set on initial topology
     **/
    private Set<NodeTemplate> getNodesOfType(Topology topology, String type, ToscaContext.Context toscaContext) {
        Set<NodeTemplate> result = new HashSet<NodeTemplate>();
        for (NodeTemplate nodeTemplate : safe(topology.getNodeTemplates()).values()) {
            if (nodeTemplate.getType().equals(type)) {
                result.add(nodeTemplate);
            } else {
                NodeType nodeType = toscaContext.getElement(NodeType.class, nodeTemplate.getType(), false);
                if (nodeType.getDerivedFrom().contains(type)) {
                    result.add(nodeTemplate);
                }
            }
        }
        return result;
    }

    private NodeTemplate getImmediateHostTemplate(Topology topology, NodeTemplate template, ToscaContext.Context toscaContext) {
        RelationshipTemplate host = getRelationshipFromType(template, NormativeRelationshipConstants.HOSTED_ON, toscaContext);
        if (host == null) {
            return null;
        }
        return topology.getNodeTemplates().get(host.getTarget());
    }

    private RelationshipTemplate getRelationshipFromType(NodeTemplate template, String type, ToscaContext.Context toscaContext) {
        return getRelationshipFromType(template, type, id -> toscaContext.getElement(RelationshipType.class, id, true));
    }

    private RelationshipTemplate getRelationshipFromType(NodeTemplate template, String type, IRelationshipTypeFinder toscaTypeFinder) {
        for (RelationshipTemplate relationshipTemplate : safe(template.getRelationships()).values()) {
            RelationshipType relationshipType = toscaTypeFinder.findElement(relationshipTemplate.getType());
            if (relationshipType != null && ToscaTypeUtils.isOfType(relationshipType, type)) {
                return relationshipTemplate;
            }
        }
        return null;
    }

}
