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
import org.alien4cloud.tosca.model.templates.NodeTemplate;
import org.alien4cloud.tosca.model.templates.PolicyTemplate;
import org.alien4cloud.tosca.model.templates.RelationshipTemplate;
import org.alien4cloud.tosca.model.templates.Requirement;
import org.alien4cloud.tosca.model.templates.Topology;
import org.alien4cloud.tosca.model.types.RelationshipType;
import org.alien4cloud.tosca.normative.constants.NormativeRelationshipConstants;
import org.alien4cloud.tosca.utils.TopologyNavigationUtil;
import org.alien4cloud.tosca.utils.ToscaTypeUtils;

import static org.alien4cloud.plugin.consulpublisher.policies.ConsulPublisherPolicyConstants.CONSULPUBLISHER_POLICY1;
import static org.alien4cloud.plugin.consulpublisher.policies.ConsulPublisherPolicyConstants.CONSULPUBLISHER_POLICY2;
import static org.alien4cloud.plugin.kubernetes.csar.Version.K8S_CSAR_VERSION;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.A4C_KUBERNETES_ADAPTER_MODIFIER_TAG_REPLACEMENT_NODE_FOR;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.K8S_TYPES_KUBECONTAINER;
import static org.alien4cloud.plugin.kubernetes.modifier.KubernetesAdapterModifier.NAMESPACE_RESOURCE_NAME;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_DEPLOYMENT_RESOURCE;
import static org.alien4cloud.plugin.kubernetes.modifier.KubeTopologyUtils.K8S_TYPES_SIMPLE_RESOURCE;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.Set;

@Slf4j
@Component("ssi-network_policy-modifier")
public class SSINetworkPolicy extends TopologyModifierSupport {

    private final ObjectMapper mapper = new ObjectMapper();

    private final String DATASTORE_RELATIONSHIP = "artemis.relationships.pub.ConnectsToDataStore";

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
       /* we are searching elements on initial topology */
       ToscaContext.init(init_topology.getDependencies());

       /* get consul publisher policies */
       Set<PolicyTemplate> policiesIhm = TopologyNavigationUtil.getPoliciesOfType(init_topology, CONSULPUBLISHER_POLICY1, true);
       Set<PolicyTemplate> policiesApi = TopologyNavigationUtil.getPoliciesOfType(init_topology, CONSULPUBLISHER_POLICY2, true);

       /* keep kube config for network policies */
       AbstractPropertyValue configPV = null;

       boolean hasDs = false,
               hasIhm = false,
               hasApi = false;

       /* process all kube deployment resources nodes */
       for (NodeTemplate node: safe(kubeNodes)) {
          log.info("Processing node " + node.getName());

          /* any kube config will do */
          configPV = node.getProperties().get("kube_config");
  
          boolean ds = false,
                  ihm = false,
                  api = false;

          /* look for node in initial topology */
          String initialNodeName  = TopologyModifierSupport.getNodeTagValueOrNull(node, A4C_KUBERNETES_ADAPTER_MODIFIER_TAG_REPLACEMENT_NODE_FOR);
          NodeTemplate initialNode = init_topology.getNodeTemplates().get(initialNodeName);

          if (initialNode == null) {
             log.warn ("Can not find initial node for " + node.getName());
          } else {
             if (usesDataStore (initialNode, init_topology)) {
                log.info (node.getName() + " uses datastore(s).");
                ds = true;
                hasDs = true;
             }
             if (exposes(initialNode, init_topology, policiesIhm)) {
                log.info (node.getName() + " exposes IHM.");
                ihm = true;
                hasIhm = true;
             }
             if (exposes(initialNode, init_topology, policiesApi)) {
                log.info (node.getName() + " exposes API.");
                api = true;
                hasApi = true;
             }
          }

          ScalarPropertyValue specProp = (ScalarPropertyValue) node.getProperties().get("resource_spec");
          try {
              ObjectNode spec = (ObjectNode) mapper.readTree(PropertyUtil.getScalarValue(specProp));

              addLabel (spec, "pod-pf-role", "module");
              addLabel (spec, "pod-util-admin", "util");
              addLabel (spec, "expose-ihm", Boolean.toString(ihm));
              addLabel (spec, "expose-api", Boolean.toString(api));
              addLabel (spec, "access-iad", Boolean.toString(ds));
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
          generateNetworkPolicies (topology, namespace, zds, configPV, kubeNodes, hasDs, hasIhm, hasApi);
       }
    }

    /**
     * tests whether given node uses datastore(s) or not
     **/
    private boolean usesDataStore (NodeTemplate node, Topology topology) {
       /**
        * input node is KubeDeployment
        * look for KubeContainer node hostedOn this node
        * look for relationship datastore on this KubeContainer node
        * true if there is at least one such relationship
        **/
       Set<NodeTemplate> containerNodes = TopologyNavigationUtil.getNodesOfType(topology, K8S_TYPES_KUBECONTAINER, true);
       for (NodeTemplate containerNode : safe(containerNodes)) {
          NodeTemplate host = TopologyNavigationUtil.getImmediateHostTemplate(topology, containerNode);
          if (host == node) {
             if (hasDataStoreRelationship(containerNode)) {
                return true;
             }
          }
       }
       return false;
    }

    /**
     * tests whether given node has relationship to datastore or not
     **/
    private boolean hasDataStoreRelationship (NodeTemplate node) {
       for (RelationshipTemplate relationshipTemplate : safe(node.getRelationships()).values()) {
          if (relationshipTemplate.getType().equals(DATASTORE_RELATIONSHIP)) {
             return true;
          }
       }
       return false;
    }

    /** 
     * tests whether given node uses given policy or not
     *  policy : target = service
     *  service : relationship connectsTo : container
     *  container : relationship hostedOn : deployment
     **/
    private boolean exposes (NodeTemplate node, Topology topology, Set<PolicyTemplate> policies) {
       for (PolicyTemplate policy : safe(policies)) {
          for (NodeTemplate service : TopologyNavigationUtil.getTargetedMembers(topology, policy)) {
             NodeTemplate container = getConnectsTo (topology, service);
             NodeTemplate deployment = TopologyNavigationUtil.getImmediateHostTemplate(topology, container);
             if (deployment == node) {
                return true;
             }
          }
       }
       return false;
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
                                          Set<NodeTemplate> deployNodes, boolean ds, boolean ihm, boolean api) {
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
       
       if (ds) {
          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-iad-util-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-iad-util-policy\n" + 
                 "spec:\n" +
                 "  podSelector:\n" +
                 "    matchLabels:\n" +
                 "      access-iad: \"true\"\n" +
                 "      pod-util-admin: util\n" +
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
                 "          pod-pf-role: iad\n" +
                 "          pod-util-admin: util\n";

          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_iad_util_policy", "a4c-iad-util-policy", configPV);

          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-iad-admin-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-iad-admin-policy\n" + 
                 "spec:\n" +
                 "  podSelector:\n" +
                 "    matchLabels:\n" +
                 "      access-iad: \"true\"\n" +
                 "      pod-util-admin: admin\n" +
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
                 "          pod-pf-role: iad\n" +
                 "          pod-util-admin: admin\n";

          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_iad_admin_policy", "a4c-iad-admin-policy", configPV);
       }

       if (ihm) {
          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-ihm-util-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-ihm-util-policy\n" + 
                 "spec:\n" +
                 "  podSelector:\n" +
                 "    matchLabels:\n" +
                 "      expose-ihm: \"true\"\n" +
                 "      pod-util-admin: util\n" +
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
                 "         pod-util-admin: util\n";

          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_ihm_util_policy", "a4c-ihm-util-policy", configPV);

          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-ihm-admin-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-ihm-admin-policy\n" + 
                 "spec:\n" +
                 "  podSelector:\n" +
                 "    matchLabels:\n" +
                 "      expose-ihm: \"true\"\n" +
                 "      pod-util-admin: admin\n" +
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
                 "         pod-util-admin: admin\n";

          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_ihm_admin_policy", "a4c-ihm-admin-policy", configPV);
       }

       if (api) {
          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-api-util-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-api-util-policy\n" + 
                 "spec:\n" +
                 "  podSelector:\n" +
                 "    matchLabels:\n" +
                 "      expose-api: \"true\"\n" +
                 "      pod-util-admin: util\n" +
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
                 "         pod-pf-role: apigw\n" +
                 "         pod-util-admin: util\n";

          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_api_util_policy", "a4c-api-util-policy", configPV);

          resource_spec = 
                 "apiVersion: networking.k8s.io/v1\n" +
                 "kind: NetworkPolicy\n" +
                 "metadata:\n" +
                 "  name: a4c-api-admin-policy\n" +
                 "  labels:\n" + 
                 "    a4c_id: a4c-api-admin-policy\n" + 
                 "spec:\n" +
                 "  podSelector:\n" +
                 "    matchLabels:\n" +
                 "      expose-api: \"true\"\n" +
                 "      pod-util-admin: admin\n" +
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
                 "         pod-pf-role: apigw\n" +
                 "         pod-util-admin: admin\n";

          generateOneNetworkPolicy (topology, deployNodes, resource_spec, "a4c_api_admin_policy", "a4c-api-admin-policy", configPV);
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

}
