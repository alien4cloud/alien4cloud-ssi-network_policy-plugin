package org.alien4cloud.plugin.ssi_network_policy;

import alien4cloud.paas.wf.TopologyContext;
import alien4cloud.paas.wf.WorkflowSimplifyService;
import alien4cloud.paas.wf.WorkflowsBuilderService;
import alien4cloud.paas.wf.validation.WorkflowValidator;
import alien4cloud.tosca.context.ToscaContext;
import alien4cloud.tosca.context.ToscaContextual;
import alien4cloud.tosca.parser.ToscaParser;
import static alien4cloud.utils.AlienUtils.safe;
import alien4cloud.utils.PropertyUtil;

import org.alien4cloud.alm.deployment.configuration.flow.FlowExecutionContext;
import org.alien4cloud.alm.deployment.configuration.flow.TopologyModifierSupport;
import org.alien4cloud.tosca.model.CSARDependency;
import org.alien4cloud.tosca.model.definitions.ComplexPropertyValue;
import org.alien4cloud.tosca.model.definitions.ScalarPropertyValue;
import org.alien4cloud.tosca.model.templates.Capability;
import org.alien4cloud.tosca.model.templates.NodeTemplate;
import org.alien4cloud.tosca.model.templates.PolicyTemplate;
import org.alien4cloud.tosca.model.templates.RelationshipTemplate;
import org.alien4cloud.tosca.model.templates.Requirement;
import org.alien4cloud.tosca.model.templates.ServiceNodeTemplate;
import org.alien4cloud.tosca.model.templates.Topology;
import org.alien4cloud.tosca.model.types.AbstractToscaType;
import org.alien4cloud.tosca.model.types.NodeType;
import org.alien4cloud.tosca.model.types.RelationshipType;
import org.alien4cloud.tosca.normative.constants.NormativeRelationshipConstants;
import org.alien4cloud.tosca.utils.IRelationshipTypeFinder;
import org.alien4cloud.tosca.utils.TopologyNavigationUtil;
import org.alien4cloud.tosca.utils.ToscaTypeUtils;

import static org.alien4cloud.plugin.k8s.webhook.policies.PolicyModifier.PSEUDORESOURCE_POLICY;
import static org.alien4cloud.plugin.kubernetes.csar.Version.K8S_CSAR_VERSION;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.A4C_KUBERNETES_ADAPTER_MODIFIER_TAG_REPLACEMENT_NODE_FOR;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.K8S_TYPES_KUBECONTAINER;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.K8S_TYPES_KUBE_CLUSTER;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.NAMESPACE_RESOURCE_NAME;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_DEPLOYMENT_RESOURCE;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_SIMPLE_RESOURCE;
import static org.alien4cloud.plugin.portal.PortalConstants.API_SERVICE;
import static org.alien4cloud.plugin.portal.PortalConstants.IAM_TYPE;
import static org.alien4cloud.plugin.portal.PortalConstants.PROXIED_SERVICE;
import static alien4cloud.plugin.k8s.spark.jobs.modifier.SparkJobsModifier.K8S_TYPES_SPARK_JOBS;

import org.springframework.stereotype.Component;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import lombok.extern.slf4j.Slf4j;

import javax.inject.Inject;

import java.net.InetAddress;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Component("ssi-network_policy-modifier")
public class SSINetworkPolicy extends TopologyModifierSupport {

    @Inject
    private WorkflowSimplifyService workflowSimplifyService;
    @Inject
    private WorkflowsBuilderService workflowBuilderService;

    private final ObjectMapper mapper = new ObjectMapper();

    private final String DATASTORE_RELATIONSHIP = "artemis.relationships.pub.ConnectsToDataStore";
    private final String RELATIONSHIP_TYPE_TO_EXPLORE = "org.alien4cloud.relationships.ConnectsToStaticEndpoint";

    @Inject
    private SSINetworkPolicyConfiguration conf;

    // known datastores
    private Map<String, ImmutablePair<String,String>> dataStoreTypes = Stream.of(new Object[][] { 
        //{ "artemis.redis.pub.capabilities.Redis", "redis", "redis_endpoint" }, 
        { "artemis.mongodb.pub.capabilities.MongoDb", "mongodb", "mongodb_endpoint" }, 
        { "artemis.mariadb.pub.capabilities.Mariadb", "mariadb", "mariadb_endpoint" }, 
        { "artemis.postgresql.pub.capabilities.PostgreSQLEndpoint", "postgresql", "postgresql_endpoint" },
        { "artemis.accumulo.pub.capabilities.Accumulo", "accumulo", "accumulo_endpoint" },
        { "artemis.cassandra.pub.capabilities.CassandraDb", "cassandra", "cassandra_endpoint" },
        { "artemis.elasticsearch.pub.capabilities.ElasticSearchRestAPI", "elasticsearch", "http" },
        { "artemis.kafka.pub.capabilities.KafkaTopic", "kafka", "kafka_topic" },
        { "artemis.hadoop.pub.capabilities.HdfsRepository", "hdfs", "hdfs_repository" },
        { "artemis.ceph.pub.capabilities.CephBucketEndpoint", "ceph", "http" },
        { "artemis.kudu.pub.capabilities.KuduEndpoint", "kudu", "kudu_endpoint" },
        { "artemis.impala.pub.capabilities.ImpalaEndpoint", "impala", "impala_endpoint" }
    }).collect(Collectors.toMap(data -> (String) data[0], data -> new ImmutablePair<String,String>((String) data[1], (String) data[2])));

    // external datastores
    private Map<String, ImmutablePair<String,String>> externalDataStoreTypes = Stream.of(new Object[][] {
        { "artemis.nexus.pub.nodes.NexusService", "nexus", "nexus_endpoint"},
        { "artemis.gitlab.pub.nodes.GitlabService", "gitlab", "gitlab_endpoint" }
    }).collect(Collectors.toMap(data -> (String) data[0], data -> new ImmutablePair<String,String>((String) data[1], (String) data[2])));

    // external datastores with multiple IPs
    private Map<String, String> multiIPExternalDataStoreTypes = Stream.of(new Object[][] {
        { "artemis.janusgraph.pub.nodes.JanusGraphService", "janusgraph" }
    }).collect(Collectors.toMap(data -> (String) data[0], data -> (String) data[1]));

    @Override
    @ToscaContextual
    public void process(Topology topology, FlowExecutionContext context) {
        log.info("Processing topology " + topology.getId());
        try {
            WorkflowValidator.disableValidationThreadLocal.set(true);
            doProcess(topology, context);
        } catch (Exception e) {
            log.warn ("Couldn't process SSINetworkPolicy modifier", e);
        } finally {
            WorkflowValidator.disableValidationThreadLocal.remove();
            log.debug("Finished processing topology " + topology.getId());
        }
    }

    private boolean doProcess(Topology topology, FlowExecutionContext context) {
       Set<NodeTemplate> kubeNodes = TopologyNavigationUtil.getNodesOfType(topology, K8S_TYPES_DEPLOYMENT_RESOURCE, true);

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

       /* get initial topology */
       Topology init_topology = (Topology)context.getExecutionCache().get(FlowExecutionContext.INITIAL_TOPOLOGY);
       ToscaContext.Context toscaContext = new ToscaContext.Context(init_topology.getDependencies());

       Set<NodeTemplate> kubeClusterNodes = TopologyNavigationUtil.getNodesOfType(init_topology, K8S_TYPES_KUBE_CLUSTER, false);
       if ((kubeClusterNodes == null) || kubeClusterNodes.isEmpty()) {
          log.info("Not a kubernetes appli, nothing to do.");
          return false;
       }

       /* get kube config for network policies */
       String k8sYamlConfig = (String)context.getExecutionCache().get(K8S_TYPES_KUBE_CLUSTER);

       /* get IHM & API services */
       Set<NodeTemplate> ihmServices = TopologyNavigationUtil.getNodesOfType(init_topology, PROXIED_SERVICE, true);
       Set<NodeTemplate> apiServices = TopologyNavigationUtil.getNodesOfType(init_topology, API_SERVICE, true);

       boolean hasDs = false,
               hasExternalDs = false,
               hasIAM = false;
       Set<String> allDS = new HashSet<String>();
       Map<String, Set<ImmutablePair<String,String>>> externalDSipAndPorts = new HashMap<String, Set<ImmutablePair<String,String>>>();

       /* process all kube deployment resources nodes */
       for (NodeTemplate node: safe(kubeNodes)) {
          log.info("Processing node " + node.getName());

          boolean ihm = false,
                  api = false,
                  iam = false;
          Set<String> nodeDS = new HashSet<String>();
          Set<String> nodeXDSnames = new HashSet<String>();
          Set<String> nodeMipXDSnames = new HashSet<String>();
          Set<ImmutablePair<String,String>> nodeXDS = new HashSet<ImmutablePair<String,String>>();

          /* look for node in initial topology */
          String initialNodeName  = TopologyModifierSupport.getNodeTagValueOrNull(node, A4C_KUBERNETES_ADAPTER_MODIFIER_TAG_REPLACEMENT_NODE_FOR);
          NodeTemplate initialNode = init_topology.getNodeTemplates().get(initialNodeName);

          if (initialNode == null) {
             log.warn ("Can not find initial node for " + node.getName());
          } else {
             nodeDS = usesDataStore (initialNode, init_topology,toscaContext);
             if (!nodeDS.isEmpty()) {
                log.info (node.getName() + " uses datastore(s).");
                hasDs = true;
                allDS.addAll(nodeDS);
             }
             if (exposes(initialNode, init_topology, ihmServices)) {
                log.info (node.getName() + " exposes IHM.");
                ihm = true;
             }
             if (exposes(initialNode, init_topology, apiServices)) {
                log.info (node.getName() + " exposes API.");
                api = true;
             }
             if (isConnectedToIAM (initialNode, init_topology, toscaContext)) {
                log.info (node.getName() + " is connected to IAM.");
                iam = true;
                hasIAM = true;
             }
             for (ImmutablePair<String,String> xdsPair : externalDataStoreTypes.values()) {
                String xDS = xdsPair.getLeft();
                nodeXDS = usesExternalDataSore (initialNode, init_topology, xDS, toscaContext, context, zds);
                if (!nodeXDS.isEmpty()) {
                   log.info (node.getName() + " uses " + xDS + " external datastore(s).");
                   hasExternalDs = true;
                   nodeXDSnames.add(xDS);
                   if (externalDSipAndPorts.get(xDS) == null) {
                      externalDSipAndPorts.put(xDS, nodeXDS);
                   } else {
                      externalDSipAndPorts.get(xDS).addAll(nodeXDS);
                   }
                }
             }
             for (String xdsType : multiIPExternalDataStoreTypes.keySet()) {
                Set<NodeTemplate> dsNodes = getNodesOfType(init_topology, xdsType, toscaContext);
                for (NodeTemplate dsNode : dsNodes) {
                   nodeXDS = usesExternalDataSore (initialNode, init_topology, dsNode, toscaContext, context, zds);
                   if (!nodeXDS.isEmpty()) {
                      Capability endpoint = safe(dsNode.getCapabilities()).get(multiIPExternalDataStoreTypes.get(xdsType));
                      String xDS = "default";
                      if (endpoint != null) {
                         xDS = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("artemis_instance_name"));
                      }
                      log.info (node.getName() + " uses " + xDS + " external datastore(s).");
                      hasExternalDs = true;
                      nodeXDSnames.add(xDS);
                      nodeMipXDSnames.add(xDS);
                      externalDSipAndPorts.put(xDS, nodeXDS);
                   }
                }
             }
          }

          ScalarPropertyValue specProp = (ScalarPropertyValue) node.getProperties().get("resource_spec");
          try {
              ObjectNode spec = (ObjectNode) mapper.readTree(PropertyUtil.getScalarValue(specProp));

              addLabel (spec, "pod-pf-role", "module");
              addLabel (spec, "expose-ihm", Boolean.toString(ihm));
              addLabel (spec, "expose-api", Boolean.toString(api));
              for (String ds : nodeDS) {
                 addLabel (spec, "access-" + ds, "true");
              }
              addLabel (spec, "access-iam", Boolean.toString(iam));
              for (ImmutablePair<String,String> xdsPair : externalDataStoreTypes.values()) {
                 String xDS = xdsPair.getLeft();
                 if (nodeXDSnames.contains(xDS)) {
                    addLabel (spec, "access-ext-" + xDS, "true");
                 } else {
                    addLabel (spec, "access-ext-" + xDS, "false");
                 }
              }
              for (String xDS : nodeMipXDSnames) {
                 addLabel (spec, "access-ext-" + xDS, "true");
              }

              if ((zds != null) && !zds.trim().equals("")) {
                 spec.with("spec").with("template").with("spec").putObject("dnsConfig").putArray("searches")
                     .add ("pf-don--tunnel-iad-" + zds.replaceAll("_","-") + ".svc.cluster.local");
              }

              specProp.setValue(mapper.writeValueAsString(spec));
          } catch(IOException e) {
              log.error("Can't parse json: {}",e);
          }

          log.debug ("Updated labels for node {}", node.getName());
       }

       /* process SparkJobs nodes */
       Set<NodeTemplate> jobsNodes = TopologyNavigationUtil.getNodesOfType(topology, K8S_TYPES_SPARK_JOBS, true);
       for (NodeTemplate node: safe(jobsNodes)) {
          log.info("Processing node " + node.getName());

          Set<String> nodeDS = hasDerivedDataStoreRelationship (topology, node,ToscaContext.get());
          if (!nodeDS.isEmpty()) {
             log.info (node.getName() + " uses datastore(s).");
             hasDs = true;
             allDS.addAll(nodeDS);
          }
          addLabel2Job (topology, node, "pod-pf-role", "module");
          addLabel2Job (topology, node, "expose-ihm", "false");
          addLabel2Job (topology, node,"expose-api", "false");
          for (String ds : nodeDS) {
             addLabel2Job (topology, node, "access-" + ds, "true");
          }
          addLabel2Job (topology, node, "access-iam", "false");
          for (ImmutablePair<String,String> xdsPair : externalDataStoreTypes.values()) {
             String xDS = xdsPair.getLeft();
             Set<ImmutablePair<String,String>> nodeXDS = hasExternalDataStoreRelationship(topology, node, xDS, toscaContext, context, zds);
             if (!nodeXDS.isEmpty()) {
                log.info (node.getName() + " uses " + xDS + " external datastore(s).");
                hasExternalDs = true;
                if (externalDSipAndPorts.get(xDS) == null) {
                   externalDSipAndPorts.put(xDS, nodeXDS);
                } else {
                   externalDSipAndPorts.get(xDS).addAll(nodeXDS);
                }
                addLabel2Job (topology, node, "access-ext-" + xDS, "true");
             } else {
                addLabel2Job (topology, node, "access-ext-" + xDS, "false");
             }
          }
          for (String xdsType : multiIPExternalDataStoreTypes.keySet()) {
             Set<NodeTemplate> dsNodes = getNodesOfType(init_topology, xdsType, toscaContext);
             for (NodeTemplate dsNode : dsNodes) {
                Set<ImmutablePair<String,String>> nodeXDS = hasExternalDataStoreRelationship(topology, node, dsNode, toscaContext, context, zds);
                if (!nodeXDS.isEmpty()) {
                   Capability endpoint = safe(dsNode.getCapabilities()).get(multiIPExternalDataStoreTypes.get(xdsType));
                   String xDS = "default";
                   if (endpoint != null) {
                      xDS = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("artemis_instance_name"));
                   }
                   log.info (node.getName() + " uses " + xDS + " external datastore(s).");
                   hasExternalDs = true;
                   externalDSipAndPorts.put(xDS, nodeXDS);
                   addLabel2Job (topology, node, "access-ext-" + xDS, "true");
                }
             }
          }
          log.debug ("Updated labels for node {}", node.getName());
       }

       boolean needsApi = containsPseudoResources(init_topology) || !jobsNodes.isEmpty();

       if ((namespace != null) && !namespace.trim().equals("") &&
           (zds != null) && !zds.trim().equals("") ) {
          generateNetworkPolicies (topology, namespace, zds, k8sYamlConfig, kubeNodes, 
                                   hasDs, allDS, needsApi, hasIAM, ihmServices, apiServices, init_topology,
                                   hasExternalDs, externalDSipAndPorts, kubeNS.getName(),
                                   context.getEnvironmentContext().get().getApplication().getId() + "-" + 
                                   context.getEnvironmentContext().get().getEnvironment().getName(), context);
       }
       return true;
    }

   /**
     * tests whether given deployment is connected to an IAM node or not
     **/
    private boolean isConnectedToIAM (NodeTemplate node, Topology init_topology, ToscaContext.Context toscaContext) {
       /**
        * input node is KubeDeployment
        * look for KubeContainer node hostedOn this node
        * look for relationship to IAM type on this KubeContainer node
        **/
       Set<NodeTemplate> containerNodes = getNodesOfType(init_topology, K8S_TYPES_KUBECONTAINER, toscaContext);
       for (NodeTemplate containerNode : safe(containerNodes)) {
          NodeTemplate host = getImmediateHostTemplate(init_topology, containerNode, toscaContext);
          if (host == node) {
             for (RelationshipTemplate relationshipTemplate : safe(containerNode.getRelationships()).values()) {
                NodeTemplate target = init_topology.getNodeTemplates().get(relationshipTemplate.getTarget());
                NodeType nodeType = toscaContext.getElement(NodeType.class, target.getType(), false);
                if (nodeType.getElementId().equals(IAM_TYPE)) {
                   return true;
                }
             }
          }
       }
       return false;
    }

    /**
     * tests whether given deployment node uses external datastore(s) or not
     **/
    private Set<ImmutablePair<String,String>> usesExternalDataSore (NodeTemplate node, Topology init_topology, String xds, ToscaContext.Context toscaContext,
                                                                    FlowExecutionContext context, String zds) {
       Set<ImmutablePair<String,String>> ds = new HashSet<ImmutablePair<String,String>>();
       /**
        * input node is KubeDeployment
        * look for KubeContainer node hostedOn this node
        * look for relationship connectsTo to external DS on this KubeContainer node
        **/
       Set<NodeTemplate> containerNodes = getNodesOfType(init_topology, K8S_TYPES_KUBECONTAINER, toscaContext);
       for (NodeTemplate containerNode : safe(containerNodes)) {
          NodeTemplate host = getImmediateHostTemplate(init_topology, containerNode, toscaContext);
          if (host == node) {
             Set<ImmutablePair<String,String>> oneDs = hasExternalDataStoreRelationship(init_topology, containerNode, xds, toscaContext, context, zds);
             if (!oneDs.isEmpty()) {
                ds.addAll(oneDs);
             }
          }
       }
       return ds;
    }

    private Set<ImmutablePair<String,String>> usesExternalDataSore (NodeTemplate node, Topology init_topology, NodeTemplate xds, ToscaContext.Context toscaContext, 
                                                                    FlowExecutionContext context, String zds) {
       Set<ImmutablePair<String,String>> ds = new HashSet<ImmutablePair<String,String>>();
       /**
        * input node is KubeDeployment
        * look for KubeContainer node hostedOn this node
        * look for relationship connectsTo to external DS on this KubeContainer node
        **/
       Set<NodeTemplate> containerNodes = getNodesOfType(init_topology, K8S_TYPES_KUBECONTAINER, toscaContext);
       for (NodeTemplate containerNode : safe(containerNodes)) {
          NodeTemplate host = getImmediateHostTemplate(init_topology, containerNode, toscaContext);
          if (host == node) {
             Set<ImmutablePair<String,String>> oneDs = hasExternalDataStoreRelationship(init_topology, containerNode, xds, toscaContext, context, zds);
             if (!oneDs.isEmpty()) {
                ds.addAll(oneDs);
             }
          }
       }
       return ds;
    }

    /**
     * tests whether given node has relationship to given external datastore or not,
     * if so return associated port and ip
     **/
    private Set<ImmutablePair<String,String>> hasExternalDataStoreRelationship (Topology init_topology, NodeTemplate node, String xds, ToscaContext.Context toscaContext,
                                                                                FlowExecutionContext context, String zds) {
       Set<ImmutablePair<String,String>> ds = new HashSet<ImmutablePair<String,String>>();

       for (RelationshipTemplate relationshipTemplate : safe(node.getRelationships()).values()) {
          RelationshipType reltype = toscaContext.getElement(RelationshipType.class, relationshipTemplate.getType(), false);
          if (ToscaTypeUtils.isOfType (reltype, NormativeRelationshipConstants.CONNECTS_TO)) {
             NodeTemplate target = init_topology.getNodeTemplates().get(relationshipTemplate.getTarget());
             ImmutablePair<String,String> val = externalDataStoreTypes.get(target.getType());
             if ((val != null) && val.getLeft().equals(xds)) {
                String ip = null;
                String port = "80";
                if (target instanceof ServiceNodeTemplate) {
                   ServiceNodeTemplate serviceNodeTemplate = (ServiceNodeTemplate)target;
                   ip = safe(serviceNodeTemplate.getAttributeValues()).get("capabilities." + val.getRight() + ".ip_address");

                   /* get port from capability properties of service */
                   Capability endpoint = safe(serviceNodeTemplate.getCapabilities()).get(val.getRight());
                   if (endpoint != null) {
                      String pport = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("port"));
                      if (StringUtils.isNotEmpty(pport)) {
                         port = pport;
                      }
                   }
                }
                if (StringUtils.isEmpty(ip)) {
                   ip = "127.0.0.1";
                }
                try {
                   InetAddress in = InetAddress.getByName(ip.trim().replaceAll("<zone>", zds));
                   String sip = in.getHostAddress();
                   log.debug ("Resolving {} to {}", ip.trim().replaceAll("<zone>", zds), sip);
                   sip = sip + "/32";
                   ds.add(new ImmutablePair<String, String> (sip, port));
                } catch(Exception e) {
                   context.log().error("Can not resolve host name: {} for service {}: {}", ip, target.getName(), e.getMessage());
                   log.error("Can not resolve host name: {} for service {}: {}", ip, target.getName(), e.getMessage());
                }
             }
          }
       }
       return ds;
    }

    private Set<ImmutablePair<String,String>> hasExternalDataStoreRelationship (Topology init_topology, NodeTemplate node, NodeTemplate xds, ToscaContext.Context toscaContext, 
                                                                                FlowExecutionContext context, String zds) {
       Set<ImmutablePair<String,String>> ds = new HashSet<ImmutablePair<String,String>>();

       for (RelationshipTemplate relationshipTemplate : safe(node.getRelationships()).values()) {
          RelationshipType reltype = toscaContext.getElement(RelationshipType.class, relationshipTemplate.getType(), false);
          if (ToscaTypeUtils.isOfType (reltype, NormativeRelationshipConstants.CONNECTS_TO)) {
             NodeTemplate target = init_topology.getNodeTemplates().get(relationshipTemplate.getTarget());
             String val = multiIPExternalDataStoreTypes.get(target.getType());
             if ((val != null) && (target.getName().equals(xds.getName()))) {
                String ip = null;
                String port = "80";
                if (target instanceof ServiceNodeTemplate) {
                   ServiceNodeTemplate serviceNodeTemplate = (ServiceNodeTemplate)target;
                   ip = safe(serviceNodeTemplate.getAttributeValues()).get("capabilities." + val + ".ip_address");

                   /* get port from capability properties of service */
                   Capability endpoint = safe(serviceNodeTemplate.getCapabilities()).get(val);
                   if (endpoint != null) {
                      String pport = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("port"));
                      if (StringUtils.isNotEmpty(pport)) {
                         port = pport;
                      }
                   }
                }
                if (StringUtils.isEmpty(ip)) {
                   ip = "127.0.0.1";
                }
                for (String oneIp : ip.split(";|,")) {
                   try {
                      InetAddress in = InetAddress.getByName(oneIp.trim().replaceAll("<zone>", zds));
                      String sip = in.getHostAddress();
                      log.debug ("Resolving {} to {}", oneIp.trim().replaceAll("<zone>", zds), sip);
                      sip = sip + "/32";
                      ds.add(new ImmutablePair<String, String> (sip, port));
                   } catch(Exception e) {
                      context.log().error("Can not resolve host name: {} for service {}: {}", oneIp, xds.getName(), e.getMessage());
                      log.error("Can not resolve host name: {} for service {}: {}", oneIp, xds.getName(), e.getMessage());
                   }
                }
             }
          }
       }
       return ds;
    }

    /**
     * tests whether given deployment node uses datastore(s) or not
     **/
    private Set<String> usesDataStore (NodeTemplate node, Topology init_topology,ToscaContext.Context toscaContext) {
       Set<String> ds = new HashSet<String>();
       /**
        * input node is KubeDeployment
        * look for KubeContainer node hostedOn this node
        * look for relationship datastores on this KubeContainer node
        **/
       Set<NodeTemplate> containerNodes = getNodesOfType(init_topology, K8S_TYPES_KUBECONTAINER, toscaContext);
       for (NodeTemplate containerNode : safe(containerNodes)) {
          NodeTemplate host = getImmediateHostTemplate(init_topology, containerNode, toscaContext);
          if (host == node) {
             Set<String> oneDs = hasDerivedDataStoreRelationship(init_topology, containerNode,toscaContext);
             if (!oneDs.isEmpty()) {
                ds.addAll(oneDs);
             }
          }
       }
       return ds;
    }

    /**
     * tests whether given node has relationship derived from relationship to datastore or not, 
     * if so return associated keyword
     **/
    private Set<String> hasDerivedDataStoreRelationship (Topology topology, NodeTemplate node,ToscaContext.Context toscaContext) {
       Set<String> ds = new HashSet<String>();
       for (RelationshipTemplate relationshipTemplate : safe(node.getRelationships()).values()) {
          RelationshipType reltype = toscaContext.getElement(RelationshipType.class, relationshipTemplate.getType(), false);
          if (ToscaTypeUtils.isOfType (reltype, DATASTORE_RELATIONSHIP) ||
              ToscaTypeUtils.isOfType (reltype, RELATIONSHIP_TYPE_TO_EXPLORE)) {
             ImmutablePair<String,String> val = dataStoreTypes.get(relationshipTemplate.getRequirementType());
             
             if (val != null) {
                String access = val.getLeft();
                String capa = val.getRight();
                Capability endpoint = safe(topology.getNodeTemplates().get(relationshipTemplate.getTarget()).getCapabilities()).get(capa);
                String instname = "default";
                if (endpoint != null) {
                   instname = PropertyUtil.getScalarValue(safe(endpoint.getProperties()).get("artemis_instance_name"));
                }

                ds.add(access + "--" + instname);
             }
          }
       }
       return ds;
    }

    /** 
     * tests whether given deployment node needs IHM or API netpol
     *  service : relationship connectsTo : container
     *  container : relationship hostedOn : deployment
     **/
    private boolean exposes (NodeTemplate node, Topology topology, Set<NodeTemplate> services) {
       for (NodeTemplate service : safe(services)) {
          NodeTemplate container = getConnectsTo (topology, service);
          NodeTemplate deployment = TopologyNavigationUtil.getImmediateHostTemplate(topology, container);
          if (deployment == node) {
             return true;
          }
       }
       return false;
    }

    private String getPort (Topology topology, NodeTemplate service) {
       /* get port from capability properties of container */
       String sport = getTargetCapabilityPropertyValue(topology, service, "expose", "port");
       if (sport == null) {
          return "80";
       }
       return sport;
    }

    private String getTargetCapabilityPropertyValue(Topology topology, NodeTemplate node, String requirementName, String propertyPath) {
        Set<RelationshipTemplate> rels = TopologyNavigationUtil.getTargetRelationships(node, requirementName);
        if (rels.size() == 0) {
            return null;
        }
        RelationshipTemplate rel = rels.iterator().next();
        NodeTemplate targetNode = topology.getNodeTemplates().get(rel.getTarget());
        Capability capability = targetNode.getCapabilities().get(rel.getTargetedCapabilityName());
        return PropertyUtil.getScalarPropertyValueFromPath(capability.getProperties(), propertyPath);
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
     * add label to job node labels 
     **/
    private void addLabel2Job(Topology topology, NodeTemplate node, String key, String value) {
       ComplexPropertyValue labelsPV = (ComplexPropertyValue)safe(node.getProperties()).get("labels");
       Map<String,Object> labels = new HashMap<String,Object>();
       if (labelsPV != null) {
          labels = labelsPV.getValue();
       }
       labels.put (key, new ScalarPropertyValue(value));
       setNodePropertyPathValue(null, topology, node, "labels", new ComplexPropertyValue(labels));
    }

    /**
     * generate all required network policies for namespace 
     **/
    private void generateNetworkPolicies (Topology topology, String namespace, String zds, String config,
                                          Set<NodeTemplate> deployNodes, boolean ds, Set<String> allDS,
                                          boolean needsApi, boolean iam, Set<NodeTemplate> ihmServices, 
                                          Set<NodeTemplate> apiServices, Topology init_topology,
                                          boolean xds, Map<String, Set<ImmutablePair<String,String>>> externalDS,
                                          String nsNodeName, String appName, FlowExecutionContext context) {
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
       generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_default_in_policy", "a4c-default-in-policy", 
                                 config, nsNodeName, namespace);

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
       generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_default_eg_policy", "a4c-default-eg-policy", 
                                 config, nsNodeName, namespace);
       
       if ((conf.getK8sMastersIPs() == null) &&
            (conf.getK8sMasters() != null) && (conf.getK8sMasters().size() > 0)) {
          conf.setK8sMastersIPs(new ArrayList<String>());
          for (String k8sMaster : conf.getK8sMasters()) {
             try {
                InetAddress in = InetAddress.getByName(k8sMaster);
                String sip = in.getHostAddress();
                log.debug ("Resolving {} to {}", k8sMaster, sip);
                conf.getK8sMastersIPs().add(sip);
             } catch(Exception e) {
                context.log().error("Can not resolve host name: {} : {}", k8sMaster, e.getMessage());
                log.error("Can not resolve host name: {}: {}", k8sMaster, e.getMessage());
             }
          }
       }

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
              "          ns-clef-namespace: kube-system\n";
       if ((conf.getK8sMastersIPs() != null) && (conf.getK8sMastersIPs().size() > 0)) {
          for (String k8sMaster : conf.getK8sMastersIPs()) {
             resource_spec += "    - ipBlock:\n" +
              "        cidr: " + k8sMaster + "/32\n";
          }
       }
       resource_spec += "  egress:\n" +
                        "  - to:\n" +
                        "    - namespaceSelector:\n" +
                        "        matchLabels:\n" +
                        "          ns-clef-namespace: kube-system\n";
       if ((conf.getK8sMastersIPs() != null) && (conf.getK8sMastersIPs().size() > 0)) {
          for (String k8sMaster : conf.getK8sMastersIPs()) {
             resource_spec += "    - ipBlock:\n" +
              "        cidr: " + k8sMaster + "/32\n";
          }
       }
       resource_spec += "  policyTypes:\n" +
                        "  - Ingress\n" + 
                        "  - Egress\n";
       generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_kube_system_policy", "a4c-kube-system-policy", 
                                 config, nsNodeName, namespace);

       if (needsApi && (conf.getK8sMasters() != null) && (conf.getK8sMasters().size() > 0)) {
          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-kube-api-policy\n" +
                 "  labels:\n" +
                 "    a4c_id: a4c-kube-api-policy\n" +
                 "spec:\n" +
                 "  podSelector: {}\n" +
                 "  egress:\n" +
                 "  - to:\n";
          for (String k8sMaster : conf.getK8sMasters()) {
             resource_spec += "    - ipBlock:\n" +
              "        cidr: " + k8sMaster + "/32\n";
          }
          resource_spec += "  policyTypes:\n" +
                           "  - Egress\n";
          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_kube_api_policy", "a4c-kube-api-policy", 
                                    config, nsNodeName, namespace);
       }

       if (iam) {
          resource_spec = 
               "apiVersion: networking.k8s.io/v1\n" +
               "kind: NetworkPolicy\n" +
               "metadata:\n" +
               "  name: a4c-iam-policy\n" +
               "  labels:\n" +
               "    a4c_id: a4c-iam-policy\n" +
               "spec:\n" +
               "  podSelector:\n" +
               "    matchLabels:\n" +
               "      access-iam: \"true\"\n" +
               "  policyTypes:\n" +
               "  - Egress\n" +
               "  egress:\n" +
               "  - to:\n" +
               "    - namespaceSelector:\n" +
               "        matchLabels:\n" +
               "          ns-zone-de-sensibilite: " + zds + "\n" +
               "          ns-pf-role: portail\n" +
               "    - podSelector:\n" +
               "        matchLabels:\n" +
               "          pod-pf-role: iam\n";
          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_iam_policy", "a4c-iam-policy", 
                                    config, nsNodeName, namespace);
       }

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
                 "      access-" + oneDS + ": \"true\"\n" +
                 "  policyTypes:\n" +
                 "  - Egress\n" +
                 "  egress:\n" +
                 "  - to:\n" +
                 "    - namespaceSelector:\n" +
                 "        matchLabels:\n" +
                 "          ns-zone-de-sensibilite: " + zds + "\n" +
                 "          ns-pf-role: iad\n" +
                 "      podSelector:\n" +
                 "        matchLabels:\n" +
                 "          pod-pf-role: " + oneDS + "\n"; 

             generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_" + a4cds + "_policy", "a4c-" + oneDS + "-policy", 
                                       config, nsNodeName, namespace); 
             log.debug ("set policy for datastore {}", oneDS);
          }
       }

       for (NodeTemplate service : ihmServices) {
          RelationshipTemplate relation = TopologyNavigationUtil.getRelationshipFromType(service, NormativeRelationshipConstants.CONNECTS_TO);
          NodeTemplate module = init_topology.getNodeTemplates().get(relation.getTarget());

          String k8sname = "-" + appName.toLowerCase() + "-" + module.getName().toLowerCase();
          String a4cname = k8sname.replaceAll("-","_");

          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-ihm" + k8sname + "-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-ihm" + k8sname + "-policy\n" + 
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
                 "      podSelector:\n" +
                 "       matchLabels:\n" +
                 "         pod-pf-role: rproxy-rp" + k8sname + "\n" +
                 "    ports:\n" + 
                 "       - port: " + getPort (init_topology, service) + "\n";
          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_ihm" + a4cname + "_policy", "a4c-ihm" + k8sname + "-policy", config, nsNodeName, namespace);
       }

       Set<String> ports = new HashSet<String>();
       for (NodeTemplate service : apiServices) {
          RelationshipTemplate relation = TopologyNavigationUtil.getRelationshipFromType(service, NormativeRelationshipConstants.CONNECTS_TO);
          NodeTemplate module = init_topology.getNodeTemplates().get(relation.getTarget());
          ports.add(getPort (init_topology, service));
       }

       if (!ports.isEmpty()) {
          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-apigw-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-apigw-policy\n" + 
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
                 "      podSelector:\n" +
                 "       matchLabels:\n" +
                 "         pod-pf-role: apigw\n" +
                 "    ports:\n";
          for (String port : ports) {
              resource_spec += "       - port: " + port + "\n";
          }
          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_apigw_policy", "a4c-apigw-policy", config, nsNodeName, namespace);
       }

       if (xds) {
          int count = 0;
          for (String xdsname : externalDS.keySet()) {
             for (ImmutablePair<String, String> ipAndPort : externalDS.get(xdsname)) {
                count++;
                String ip = ipAndPort.getLeft();
                String port = ipAndPort.getRight();
                resource_spec = 
                    "apiVersion: networking.k8s.io/v1\n" +
                    "kind: NetworkPolicy\n" +
                    "metadata:\n" +
                    "  name: a4c-eg-ext-" + count + "-policy\n" +
                    "  labels:\n" + 
                    "    a4c_id: a4c-eg-ext-" + count + "-policy\n" + 
                    "spec:\n" +
                    "  podSelector:\n" +
                    "    matchLabels:\n" +
                    "      access-ext-" + xdsname + ": \"true\"\n" +
                    "  policyTypes:\n" +
                    "  - Egress\n" +
                    "  egress:\n" +
                    "  - to:\n" +
                    "    - ipBlock:\n" +
                    "        cidr: " + ip + "\n" +
                    "    ports:\n" +
                    "        - port: " + port + "\n";

                generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_eg_ext_" + count + "_policy", "a4c-eg-ext-" + count + "-policy", 
                                       config, nsNodeName, namespace);
             }
          }
       }

    }

    /**
     * generate a network policies for namespace 
     **/
    private void generateOneNetworkPolicy (Topology topology, Set<NodeTemplate> deployNodes, String resource_spec, String policyNodeName,
                                           String policyName, String config, String nsNodeName, String namespace) {
       /* create SimpleResource with props resource_id, resource_type, resource_spec and kube_config */
       NodeTemplate polResourceNode = addNodeTemplate(null, topology, policyNodeName, K8S_TYPES_SIMPLE_RESOURCE, getK8SCsarVersion(topology));

       setNodePropertyPathValue(null, topology, polResourceNode, "resource_id", new ScalarPropertyValue(policyName));
       setNodePropertyPathValue(null, topology, polResourceNode, "resource_type", new ScalarPropertyValue("networkpolicy"));
       setNodePropertyPathValue(null, topology, polResourceNode, "kube_config", new ScalarPropertyValue(config));
       setNodePropertyPathValue(null, topology, polResourceNode, "resource_spec", new ScalarPropertyValue(resource_spec));
       setNodePropertyPathValue(null, topology, polResourceNode, "namespace", new ScalarPropertyValue(namespace));

       /* add relations */
       for (NodeTemplate deploymentResourceNode : safe(deployNodes)) {
           addRelationshipTemplate (null,
                                    topology,
                                    deploymentResourceNode,
                                    policyNodeName,
                                    NormativeRelationshipConstants.DEPENDS_ON,
                                    "dependency",
                                    "feature");
           log.debug ("adding relation {} -> {}", deploymentResourceNode.getName(), policyNodeName);
       }

       /* add relation to namespace node */
       addRelationshipTemplate(null, topology, polResourceNode, nsNodeName, NormativeRelationshipConstants.DEPENDS_ON, "dependency", "feature");
    }

    /**
     * get CSAR version from dependencies if any
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

   public boolean containsPseudoResources (Topology topology) {
        /* get all PseudoResource policies targets on topology */
        Set<String> pseudoResources = new HashSet<String>();
        Set<PolicyTemplate> policies = TopologyNavigationUtil.getPoliciesOfType(topology, PSEUDORESOURCE_POLICY, true);
        for (PolicyTemplate policy : policies) {
           /* get all target nodes on current policy */
           pseudoResources.addAll(safe(policy.getTargets()));
        }
        return (pseudoResources.size() > 0);
   }

}
