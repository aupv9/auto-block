package io.autoblock.spring;

import io.autoblock.spring.config.AutoBlockProperties;
import io.autoblock.spring.core.DecayWorker;
import io.autoblock.spring.core.RedisOps;
import io.autoblock.spring.core.RateLimiter;
import io.autoblock.spring.core.RulesWatcher;
import io.autoblock.spring.filter.AutoBlockFilter;
import io.autoblock.spring.filter.AutoBlockWebFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.StringRedisTemplate;

import jakarta.servlet.Filter;

/**
 * Spring Boot auto-configuration for AutoBlock.
 *
 * Registers shared beans ({@link RedisOps}, {@link RateLimiter}) unconditionally
 * (assuming Redis + autoblock.enabled), then activates the correct filter
 * depending on the web stack:
 *
 * <ul>
 *   <li>Servlet (Spring MVC): {@link AutoBlockFilter} via {@link FilterRegistrationBean}</li>
 *   <li>Reactive (WebFlux):   {@link AutoBlockWebFilter} via {@link org.springframework.web.server.WebFilter}</li>
 * </ul>
 *
 * To disable entirely: {@code autoblock.enabled=false}
 * To customise: declare your own {@link AutoBlockFilter} or {@link AutoBlockWebFilter} bean.
 */
@AutoConfiguration(after = RedisAutoConfiguration.class)
@ConditionalOnProperty(prefix = "autoblock", name = "enabled", matchIfMissing = true)
@ConditionalOnClass(StringRedisTemplate.class)
@EnableConfigurationProperties(AutoBlockProperties.class)
public class AutoBlockAutoConfiguration {

    // ---- Shared beans (both servlet and reactive) -------------------------

    @Bean
    @ConditionalOnMissingBean
    public RedisOps autoBlockRedisOps(StringRedisTemplate redisTemplate) {
        return new RedisOps(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public RateLimiter autoBlockRateLimiter(AutoBlockProperties props, RedisOps redisOps) {
        return new RateLimiter(props, redisOps);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "autoblock.hot-reload", name = "enabled", matchIfMissing = true)
    public RulesWatcher autoBlockRulesWatcher(
        RateLimiter limiter, RedisOps redisOps, AutoBlockProperties props
    ) {
        return new RulesWatcher(limiter, redisOps, props);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "autoblock.decay", name = "enabled", matchIfMissing = true)
    public DecayWorker autoBlockDecayWorker(
        StringRedisTemplate redisTemplate, AutoBlockProperties props
    ) {
        return new DecayWorker(redisTemplate, props);
    }

    // ---- Servlet (Spring MVC) --------------------------------------------

    /**
     * Activated only when {@code jakarta.servlet.Filter} is on the classpath
     * and the app is a traditional servlet container.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(Filter.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    static class ServletConfiguration {

        @Bean
        @ConditionalOnMissingBean(AutoBlockFilter.class)
        public FilterRegistrationBean<AutoBlockFilter> autoBlockFilter(
            RateLimiter limiter,
            AutoBlockProperties props
        ) {
            var filter       = new AutoBlockFilter(limiter, props);
            var registration = new FilterRegistrationBean<>(filter);
            // Run before Spring Security (default order -100)
            registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
            registration.addUrlPatterns("/*");
            registration.setName("autoBlockFilter");
            return registration;
        }
    }

    // ---- Reactive (WebFlux) ----------------------------------------------

    /**
     * Activated only when Reactor + WebFlux are on the classpath
     * and the app is a reactive web application.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(reactor.core.publisher.Mono.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    static class ReactiveConfiguration {

        @Bean
        @ConditionalOnMissingBean(AutoBlockWebFilter.class)
        public AutoBlockWebFilter autoBlockWebFilter(
            RateLimiter limiter,
            AutoBlockProperties props
        ) {
            return new AutoBlockWebFilter(limiter, props);
        }
    }
}
