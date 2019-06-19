package com.hsy.gateway.provider;

import java.util.ArrayList;
import java.util.List;

import org.springframework.cloud.gateway.discovery.DiscoveryClientRouteDefinitionLocator;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import springfox.documentation.swagger.web.SwaggerResource;
import springfox.documentation.swagger.web.SwaggerResourcesProvider;

/**
 * @author 张梓枫
 * @Description
 * @date:   2019年1月18日 上午10:28:39
 */
@Component
@Primary
public class SwaggerProvider implements SwaggerResourcesProvider{
    
    public static final String API_URI = "/v2/api-docs";

    public static final String EUREKA_SUB_PRIX = "CompositeDiscoveryClient_";
    
    public static final String GATEWAY_SUB_PRIX = "GATEWAY";

    private final DiscoveryClientRouteDefinitionLocator routeLocator;

    public SwaggerProvider(DiscoveryClientRouteDefinitionLocator routeLocator) {

        this.routeLocator = routeLocator;

    }

    @Override
    public List<SwaggerResource> get() {

        List<SwaggerResource> resources = new ArrayList<>();

        //从DiscoveryClientRouteDefinitionLocator 中取出routes，构造成swaggerResource
        routeLocator.getRouteDefinitions().subscribe(routeDefinition -> {
            System.out.println(routeDefinition.getId());
          if (!routeDefinition.getId().contains(GATEWAY_SUB_PRIX)){
              resources.add(swaggerResource(routeDefinition.getId().substring(EUREKA_SUB_PRIX.length()),routeDefinition.getPredicates().get(0).getArgs().get("pattern").replace("/**", API_URI)));
          }
        });

        return resources;

    }

    private SwaggerResource swaggerResource(String name, String location) {

        SwaggerResource swaggerResource = new SwaggerResource();

        swaggerResource.setName(name);

        swaggerResource.setLocation(location);

        swaggerResource.setSwaggerVersion("2.0");

        return swaggerResource;

    }

}
