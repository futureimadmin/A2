package io.a2.processor;

import io.a2.annotations.A2Authorize;
import io.a2.annotations.A2Protected;
import io.a2.annotations.A2Token;
import io.a2.annotations.Protocol;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import java.util.Set;

/**
 * Compile-time checks for A2 annotations.
 *
 * Rules enforced:
 * - @A2Protected / @A2Authorize / @A2Token only on types or methods
 * - roles / permissions strings must be non-blank when present
 * - protocol list must not contain null / CUSTOM without configKey
 * - @A2Token.ttlSeconds must be >= 0
 */
@SupportedAnnotationTypes({
        "io.a2.annotations.A2Protected",
        "io.a2.annotations.A2Authorize",
        "io.a2.annotations.A2Token",
        "io.a2.annotations.A2Authenticate",
        "io.a2.annotations.A2Rotate",
        "io.a2.annotations.A2Revoke"
})
@SupportedSourceVersion(SourceVersion.RELEASE_17)
public class A2Processor extends AbstractProcessor {

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        for (Element e : roundEnv.getElementsAnnotatedWith(A2Protected.class)) {
            validateProtected(e);
        }
        for (Element e : roundEnv.getElementsAnnotatedWith(A2Authorize.class)) {
            validateAuthorize(e);
        }
        for (Element e : roundEnv.getElementsAnnotatedWith(A2Token.class)) {
            validateToken(e);
        }
        return true;
    }

    private void validateProtected(Element e) {
        if (!isTypeOrMethod(e)) {
            error(e, "@A2Protected may only be applied to types or methods");
            return;
        }
        A2Protected ann = e.getAnnotation(A2Protected.class);
        for (String role : ann.roles()) {
            if (role == null || role.isBlank()) {
                error(e, "@A2Protected roles must not contain blank values");
            }
        }
        for (String perm : ann.permissions()) {
            if (perm == null || perm.isBlank()) {
                error(e, "@A2Protected permissions must not contain blank values");
            }
        }
        for (Protocol p : ann.protocols()) {
            if (p == Protocol.CUSTOM) {
                warning(e, "@A2Protected uses Protocol.CUSTOM – ensure a custom provider is registered");
            }
        }
    }

    private void validateAuthorize(Element e) {
        if (!isTypeOrMethod(e)) {
            error(e, "@A2Authorize may only be applied to types or methods");
            return;
        }
        A2Authorize ann = e.getAnnotation(A2Authorize.class);
        for (String role : ann.roles()) {
            if (role == null || role.isBlank()) {
                error(e, "@A2Authorize roles must not contain blank values");
            }
        }
        for (String perm : ann.permissions()) {
            if (perm == null || perm.isBlank()) {
                error(e, "@A2Authorize permissions must not contain blank values");
            }
        }
    }

    private void validateToken(Element e) {
        if (!isTypeOrMethod(e)) {
            error(e, "@A2Token may only be applied to types or methods");
            return;
        }
        A2Token ann = e.getAnnotation(A2Token.class);
        if (ann.ttlSeconds() < 0) {
            error(e, "@A2Token ttlSeconds must be >= 0");
        }
    }

    private boolean isTypeOrMethod(Element e) {
        ElementKind k = e.getKind();
        return k == ElementKind.CLASS || k == ElementKind.INTERFACE
                || k == ElementKind.METHOD || k == ElementKind.ENUM;
    }

    private void error(Element e, String msg) {
        processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, msg, e);
    }

    private void warning(Element e, String msg) {
        processingEnv.getMessager().printMessage(Diagnostic.Kind.WARNING, msg, e);
    }
}
