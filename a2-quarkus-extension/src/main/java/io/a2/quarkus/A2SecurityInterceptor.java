package io.a2.quarkus;

import io.a2.core.interceptor.A2Interceptor;
import jakarta.annotation.Priority;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;

@A2InterceptorBinding
@Interceptor
@Priority(Interceptor.Priority.LIBRARY_BEFORE + 10)
public class A2SecurityInterceptor {

    private final A2Interceptor delegate = new A2Interceptor();

    @AroundInvoke
    public Object enforce(InvocationContext ctx) throws Exception {
        delegate.before(ctx.getTarget(), ctx.getMethod(), ctx.getParameters());
        Object result = ctx.proceed();
        delegate.afterSuccess(ctx.getTarget(), ctx.getMethod(), result);
        return result;
    }
}
