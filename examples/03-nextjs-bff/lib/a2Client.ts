import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import path from "node:path";

function resolveProtoPath(): string {
  if (process.env.A2_PROTO) return process.env.A2_PROTO;
  return path.join(process.cwd(), "../../a2-sidecar/src/main/proto/a2.proto");
}

export function createA2Client(address = process.env.A2_SIDECAR ?? "localhost:50051") {
  const def = protoLoader.loadSync(resolveProtoPath(), {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const proto = grpc.loadPackageDefinition(def) as any;
  return new proto.a2.A2Service(address, grpc.credentials.createInsecure());
}

export function promisify<T>(fn: (cb: (err: Error | null, res: T) => void) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    fn((err, res) => (err ? reject(err) : resolve(res)));
  });
}
