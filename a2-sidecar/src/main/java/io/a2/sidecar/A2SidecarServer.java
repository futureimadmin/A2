package io.a2.sidecar;

import io.a2.core.A2Runtime;
import io.a2.core.DefaultTokenService;
import io.a2.provider.apikey.ApiKeyProtocolProvider;
import io.a2.provider.jwt.JwtProtocolProvider;
import io.a2.provider.oidc.OidcProtocolProvider;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stand-alone gRPC sidecar process.
 *
 * Usage:
 *   java -jar a2-sidecar.jar [--port 50051]
 *
 * Any language can now call Authenticate / Authorize / IssueToken / etc.
 * without embedding the Java runtime.
 */
public class A2SidecarServer {

    private static final Logger log = LoggerFactory.getLogger(A2SidecarServer.class);

    public static void main(String[] args) throws Exception {
        int port = 50051;
        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            }
        }

        // bootstrap providers
        A2Runtime runtime = A2Runtime.get();
        runtime.register(new JwtProtocolProvider());
        runtime.register(new ApiKeyProtocolProvider());
        runtime.register(new OidcProtocolProvider());
        runtime.setTokenService(new DefaultTokenService());

        Server server = ServerBuilder.forPort(port)
                .addService(new A2GrpcService())
                .build()
                .start();

        log.info("A2 Sidecar listening on port {}", port);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutting down A2 Sidecar...");
            server.shutdown();
        }));
        server.awaitTermination();
    }
}
