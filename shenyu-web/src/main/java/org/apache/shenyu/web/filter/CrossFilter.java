/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shenyu.web.filter;

import java.util.Arrays;
import java.util.HashSet;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.shenyu.common.config.ShenyuConfig.CrossFilterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The type Cross filter.
 */
public class CrossFilter implements WebFilter {

    private static final Logger LOG = LoggerFactory.getLogger(CrossFilter.class);

    private static final String ALL = "*";

    /**
     * 自定义跨域的域名后缀.
     */
    private static final Set<String> ALLOWED_ORIGIN_SET = new HashSet<>(Arrays.asList(
        "davinci.com",
        "xiaojukeji.com"
    ));

    private final CrossFilterConfig filterConfig;

    public CrossFilter(final CrossFilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    @Override
    @NonNull
    public Mono<Void> filter(@NonNull final ServerWebExchange exchange, @NonNull final WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        if (CorsUtils.isCorsRequest(request)) {
            ServerHttpResponse response = exchange.getResponse();
            HttpHeaders headers = response.getHeaders();
            // "Access-Control-Allow-Origin"
            // if the allowed origin is empty use the request 's origin
            /*if (StringUtils.isBlank(this.filterConfig.getAllowedOrigin())) {
                headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, request.getHeaders().getOrigin());
            } else {
                this.filterSameHeader(headers, HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                        this.filterConfig.getAllowedOrigin());
            }*/
            this.filterSameHeader(headers, HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                getAllowedOrigin(request));
            // "Access-Control-Allow-Methods"
            this.filterSameHeader(headers, HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                this.filterConfig.getAllowedMethods());
            // "Access-Control-Max-Age"
            this.filterSameHeader(headers, HttpHeaders.ACCESS_CONTROL_MAX_AGE,
                this.filterConfig.getMaxAge());
            // "Access-Control-Allow-Headers"
            this.filterSameHeader(headers, HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                this.filterConfig.getAllowedHeaders());
            // "Access-Control-Expose-Headers"
            this.filterSameHeader(headers, HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,
                this.filterConfig.getAllowedExpose());
            // "Access-Control-Allow-Credentials"
            this.filterSameHeader(headers, HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,
                String.valueOf(this.filterConfig.isAllowCredentials()));
            if (request.getMethod() == HttpMethod.OPTIONS) {
                response.setStatusCode(HttpStatus.OK);
                return Mono.empty();
            }
        }
        return chain.filter(exchange);
    }

    /**
     * Filter the same headers.
     *
     * @param headers the response headers
     * @param header header name
     * @param newHeaderValue the new value for header
     */
    private void filterSameHeader(final HttpHeaders headers, final String header, final String newHeaderValue) {
        if (StringUtils.isBlank(newHeaderValue)) {
            return;
        }
        if (ALL.equals(newHeaderValue.trim())) {
            headers.set(header, ALL);
            return;
        }
        final Set<String> newHeaders = Stream.of(newHeaderValue.split(","))
                .map(String::trim).collect(Collectors.toSet());
        List<String> originHeaders = headers.get(header);
        if (CollectionUtils.isNotEmpty(originHeaders)) {
            if (originHeaders.contains(ALL)) {
                return;
            }
            originHeaders = Stream.of(String.join(",", originHeaders).split(","))
                    .map(String::trim).collect(Collectors.toList());
            newHeaders.addAll(originHeaders);
        }
        headers.set(header, String.join(",", newHeaders));
    }

    /**
     * 自定义跨域.
     *
     * @param request 请求
     * @return check真烦
     */
    public String getAllowedOrigin(final ServerHttpRequest request) {
        String origin = request.getHeaders().getOrigin();
        LOG.info("CrossFilter getAllowedOrigin start origin={} path={}", origin, request.getPath());
        if (StringUtils.isEmpty(origin)) {
            LOG.error("CrossFilter 不支持跨域");
            return "";
        }

        UriComponents originUrl = UriComponentsBuilder.fromOriginHeader(origin).build();
        if (originUrl != null && originUrl.getHost() != null) {
            for (String allowed : ALLOWED_ORIGIN_SET) {
                if (originUrl.getHost().contains(allowed)) {
                    return origin;
                }
            }
        }
        String appid = request.getQueryParams().getFirst("appid");
        if (StringUtils.isNotEmpty(appid) && "10007001".equals(appid)) {
            return origin;
        }

        LOG.error("CrossFilter 不支持跨域 origin={}", origin);
        return "";
    }

}
