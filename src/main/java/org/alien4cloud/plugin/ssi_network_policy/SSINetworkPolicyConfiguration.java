package org.alien4cloud.plugin.ssi_network_policy;

import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Getter
@Setter
@Component
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "alien4cloud-ssi-network_policy-plugin")
public class SSINetworkPolicyConfiguration {
   private List<String> k8sMasters;
}
