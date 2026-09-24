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
            + "|| @within(io.a2.annotations.A2Authorize) || @annotation(io.a2.annotations.A2Authorize)")
    public Object enforce(ProceedingJoinPoint pjp) throws Throwable {
        Method method = ((MethodSignature) pjp.getSignature()).getMethod();
        Object target = pjp.getTarget();
        Object[] args = pjp.getArgs();

        interceptor.before(target, method, args);
        Object result = pjp.proceed();
        interceptor.afterSuccess(target, method, result);
        return result;
    }
}
