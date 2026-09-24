package io.a2.sidecar;

import io.a2.annotations.Protocol;
import io.a2.annotations.TokenType;
import io.a2.core.A2Runtime;
import io.a2.core.DefaultSecurityContext;
import io.a2.core.SimplePrincipal;
import io.a2.sidecar.grpc.A2ServiceGrpc;
import io.a2.sidecar.grpc.AuthRequest;
import io.a2.sidecar.grpc.AuthResponse;
import io.a2.sidecar.grpc.AuthorizeRequest;
import io.a2.sidecar.grpc.AuthorizeResponse;
import io.a2.sidecar.grpc.IntrospectRequest;
import io.a2.sidecar.grpc.IntrospectResponse;
import io.a2.sidecar.grpc.RevokeRequest;
import io.a2.sidecar.grpc.RevokeResponse;
import io.a2.sidecar.grpc.TokenRequest;
import io.a2.sidecar.grpc.TokenResponse;
import io.a2.spi.Principal;
import io.a2.spi.model.AuthResult;
import io.a2.spi.model.AuthorizationContext;
import io.a2.spi.model.TokenResult;
import io.grpc.stub.StreamObserver;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * gRPC implementation of the A2 multi-language contract.
 * Any language can call these RPCs instead of embedding the Java runtime.
 */
public class A2GrpcService extends A2ServiceGrpc.A2ServiceImplBase {

    private final A2Runtime runtime = A2Runtime.get();

    @Override
    public void authenticate(AuthRequest request, StreamObserver<AuthResponse> responseObserver) {
        Protocol protocol = parseProtocol(request.getProtocol());
        io.a2.spi.model.AuthRequest spiReq = io.a2.spi.model.AuthRequest.builder()
                .protocol(protocol)
                .credentials(request.getCredentials())
                .headers(request.getHeadersMap())
                .attributes(new HashMap<>(request.getAttributesMap()))
                .build();

        AuthResult result = runtime.authenticate(spiReq);
        AuthResponse.Builder resp = AuthResponse.newBuilder().setSuccess(result.isSuccess());
        if (result.isSuccess()) {
            Principal p = result.principal().orElseThrow();
            resp.setPrincipalId(p.getId())
                .setPrincipalName(p.getName())
                .addAllRoles(p.getRoles())
                .addAllPermissions(p.getPermissions());
            p.getAttributes().forEach((k, v) -> resp.putClaims(k, String.valueOf(v)));
            // also set context for subsequent calls on this thread (optional)
            runtime.setContext(DefaultSecurityContext.of(p, protocol));
        } else {
            resp.setError(result.error().orElse("authentication failed"));
        }
        responseObserver.onNext(resp.build());
        responseObserver.onCompleted();
    }

    @Override
    public void authorize(AuthorizeRequest request, StreamObserver<AuthorizeResponse> responseObserver) {
        Protocol protocol = parseProtocol(request.getProtocol());
        Principal principal = SimplePrincipal.of(request.getPrincipalId(), request.getPrincipalId());
        runtime.setContext(DefaultSecurityContext.of(principal, protocol));

        AuthorizationContext ctx = new AuthorizationContext(
                runtime.currentContext(),
                Set.copyOf(request.getRequiredRolesList()),
                Set.copyOf(request.getRequiredPermissionsList()),
                request.getRequireAll(),
                ""
        );

        boolean allowed = runtime.provider(protocol)
                .map(p -> p.authorize(ctx))
                .orElseGet(() -> {
                    // fallback
                    if (request.getRequireAll()) {
                        return runtime.currentContext().roles().containsAll(request.getRequiredRolesList())
                                && runtime.currentContext().permissions().containsAll(request.getRequiredPermissionsList());
                    }
                    return request.getRequiredRolesList().isEmpty()
                            || request.getRequiredRolesList().stream().anyMatch(runtime.currentContext()::hasRole);
                });

        responseObserver.onNext(AuthorizeResponse.newBuilder()
                .setAllowed(allowed)
                .setReason(allowed ? "ok" : "denied")
                .build());
        responseObserver.onCompleted();
    }

    @Override
    public void issueToken(TokenRequest request, StreamObserver<TokenResponse> responseObserver) {
        io.a2.spi.model.TokenRequest spi = io.a2.spi.model.TokenRequest.builder()
                .type(parseTokenType(request.getType()))
                .principalId(request.getPrincipalId())
                .scopes(request.getScopesList())
                .ttlSeconds(request.getTtlSeconds())
                .protocol(parseProtocol(request.getProtocol()))
                .claims(request.getClaimsMap().entrySet().stream()
                        .collect(Collectors.toMap(Map.Entry::getKey, e -> (Object) e.getValue())))
                .build();

        TokenResult result = runtime.tokenService().issue(spi);
        responseObserver.onNext(toTokenResponse(result));
        responseObserver.onCompleted();
    }

    @Override
    public void rotateToken(TokenRequest request, StreamObserver<TokenResponse> responseObserver) {
        io.a2.spi.model.TokenRequest spi = io.a2.spi.model.TokenRequest.builder()
                .type(parseTokenType(request.getType()))
                .principalId(request.getPrincipalId())
                .scopes(request.getScopesList())
                .ttlSeconds(request.getTtlSeconds())
                .protocol(parseProtocol(request.getProtocol()))
                .existingToken(request.getExistingToken())
                .build();

        TokenResult result = runtime.tokenService().rotate(spi);
        responseObserver.onNext(toTokenResponse(result));
        responseObserver.onCompleted();
    }

    @Override
    public void revokeToken(RevokeRequest request, StreamObserver<RevokeResponse> responseObserver) {
        try {
            if (request.getAllForPrincipal() && !request.getPrincipalId().isBlank()) {
                runtime.tokenService().revokeAllForPrincipal(request.getPrincipalId());
            } else if (!request.getTokenId().isBlank()) {
                runtime.tokenService().revoke(request.getTokenId());
            }
            responseObserver.onNext(RevokeResponse.newBuilder().setSuccess(true).build());
        } catch (Exception e) {
            responseObserver.onNext(RevokeResponse.newBuilder()
                    .setSuccess(false).setError(e.getMessage()).build());
        }
        responseObserver.onCompleted();
    }

    @Override
    public void introspect(IntrospectRequest request, StreamObserver<IntrospectResponse> responseObserver) {
        var opt = runtime.tokenService().introspect(request.getToken());
        if (opt.isEmpty()) {
            responseObserver.onNext(IntrospectResponse.newBuilder().setActive(false).build());
        } else {
            TokenResult t = opt.get();
            IntrospectResponse.Builder b = IntrospectResponse.newBuilder()
                    .setActive(t.isSuccess())
                    .setTokenId(t.tokenId().orElse(""))
                    .setType(t.type().map(Enum::name).orElse(""))
                    .setExpiresAtEpoch(t.expiresAt().map(i -> i.getEpochSecond()).orElse(0L));
            t.claims().forEach((k, v) -> b.putClaims(k, String.valueOf(v)));
            responseObserver.onNext(b.build());
        }
        responseObserver.onCompleted();
    }

    private TokenResponse toTokenResponse(TokenResult result) {
        TokenResponse.Builder b = TokenResponse.newBuilder().setSuccess(result.isSuccess());
        if (result.isSuccess()) {
            b.setToken(result.token().orElse(""))
             .setTokenId(result.tokenId().orElse(""))
             .setType(result.type().map(Enum::name).orElse(""))
             .setExpiresAtEpoch(result.expiresAt().map(i -> i.getEpochSecond()).orElse(0L));
            result.claims().forEach((k, v) -> b.putClaims(k, String.valueOf(v)));
        } else {
            b.setError(result.error().orElse("token operation failed"));
        }
        return b.build();
    }

    private Protocol parseProtocol(String s) {
        if (s == null || s.isBlank()) return Protocol.JWT;
        try {
            return Protocol.valueOf(s.toUpperCase());
        } catch (Exception e) {
            return Protocol.CUSTOM;
        }
    }

    private TokenType parseTokenType(String s) {
        if (s == null || s.isBlank()) return TokenType.ACCESS;
        try {
            return TokenType.valueOf(s.toUpperCase());
        } catch (Exception e) {
            return TokenType.CUSTOM;
        }
    }
}
