package com.hsy.gateway.fitler;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.hsy.common.bean.User;
import com.hsy.common.constant.CommonConstant;
import com.hsy.common.jwt.JwtSecurityUtils;
import com.hsy.common.utils.JsonUtils;
import com.hsy.common.utils.ObjectUtils;
import com.hsy.redis.client.RedisClient;
import com.hsy.resource.constant.JwtConstant;
import com.hsy.resource.constant.SystemConstant;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * @author 张梓枫
 * @date  2019年3月19日 
 * @Description 网关拦截器，实现用户登陆认证
 */
@Slf4j
@Order(-1000)
@Component
public class AuthenticationFitler implements GlobalFilter{

    
    @Autowired
    private RedisClient<String> redisClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String url = request.getURI().getPath();
        log.info("请求的服务地址:{}", url);
		if (Arrays.asList(SystemConstant.EXCLUDE_PATH).contains(url)) {
			return chain.filter(exchange);
		}
		String token = request.getHeaders().getFirst(CommonConstant.SESSION_TOKEN);
		if (ObjectUtils.isEmpty(token)) {
			exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
			return exchange.getResponse().setComplete();
		}
		if (!redisClient.exists(token)) {
			exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
			return exchange.getResponse().setComplete();
		}
		Map<Object, Object> tokenMap = redisClient.hget(token);
		Integer expire = ObjectUtils.convertToInteger(tokenMap.get(JwtConstant.JWT_EXPIRATION));
		String json = ObjectUtils.convertToString(tokenMap.get(JwtConstant.JWT_USER));
		User user = JsonUtils.toBean(json, User.class);
		if (ObjectUtils.equals(expire, JwtConstant.JWT_EXPIRE)) {
			return chain.filter(exchange);
		}
		boolean jwtExpire = JwtSecurityUtils.isExpiration(token);
		if (jwtExpire) {
			String newToken = JwtSecurityUtils.createToken(ObjectUtils.convertToString(user.getId()), ObjectUtils.convertToString(user.getSellerId()), user.getUsername(), expire);
			this.createAgainToken(token, newToken, user, expire);
			this.setResponse(exchange.getResponse(), newToken);
		} else {
			this.againRedis(token, user, expire);
		}
        return chain.filter(exchange);
    }
    
    /**
     * @author 张梓枫
     * @param  @param token 
     * @return void
     * @throws Exception 
     * @desc  判断token在jwt中是否已经失效，如果失效，重新生成新的token，替换redis中旧的token,
     * 如果没有失效，则刷新redis的失效时间
     */
	private void createAgainToken(String token, String newToken, User user, Integer expire) {
        this.againRedis(newToken, user, expire);
        redisClient.remove(token);
    }
    
    private void setResponse(ServerHttpResponse response,String token) {
        response.getHeaders().add(CommonConstant.EXPOSE_HEADERS, CommonConstant.SESSION_TOKEN);
        response.getHeaders().add("Access-Control-Allow-Origin", "*");
        response.getHeaders().add("Content-Type", "application/json;charset=utf-8");
        response.getHeaders().add(CommonConstant.SESSION_TOKEN, token);
    }
    
    private void againRedis(String token, User user,Integer expire) {
        Map<Object, Object> userMap = new HashMap<>();
        userMap.put(JwtConstant.JWT_USER, JsonUtils.toJson(user));
        userMap.put(JwtConstant.JWT_EXPIRATION, ObjectUtils.convertToString(expire));
        redisClient.hset(token, userMap, expire);
    }

}
