package io.a2.spring;

import io.a2.core.interceptor.A2Interceptor;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.Order;

import java.lang.reflect.Method;

@Aspect
@Order(0)
public class A2SecurityAspect {

    private final A2Interceptor interceptor;

    public A2SecurityAspect(A2Interceptor interceptor) {
        this.interceptor = interceptor;
    }

    @Around("@within(io.a2.annotations.A2Protected) || @annotation(io.a2.annotations.A2Protected) "
            + "|| @within(io.a2.annotations.A2Authorize) || @annotation(io.a2.annotations.A2Authorize) "
            + "|| @within(io.a2.annotations.A2Sso) || @annotation(io.a2.annotations.A2Sso) "
            + "|| @within(io.a2.annotations.A2OktaSso) || @annotation(io.a2.annotations.A2OktaSso) "
            + "|| @within(io.a2.annotations.A2GoogleSso) || @annotation(io.a2.annotations.A2GoogleSso) "
            + "|| @within(io.a2.annotations.A2EntraSso) || @annotation(io.a2.annotations.A2EntraSso) "
            + "|| @within(io.a2.annotations.A2PingSso) || @annotation(io.a2.annotations.A2PingSso) "
            + "|| @within(io.a2.annotations.A2Auth0Sso) || @annotation(io.a2.annotations.A2Auth0Sso) "
            + "|| @within(io.a2.annotations.A2ActiveDirectorySso) || @annotation(io.a2.annotations.A2ActiveDirectorySso)")
    public Object enforce(ProceedingJoinPoint pjp) throws Throwable {
        Method method = ((MethodSignature) pjp.getSignature()).getMethod();
        interceptor.before(pjp.getTarget(), method, pjp.getArgs());
        Object result = pjp.proceed();
        interceptor.afterSuccess(pjp.getTarget(), method, result);
        return result;
    }
}
