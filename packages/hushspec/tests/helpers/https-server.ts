/**
 * A local HTTPS server for exercising the `extends` loader's transport paths
 * (core spec 2.6.4) without reaching the network.
 *
 * It is addressed as `localhost` and listens on the loopback address that name
 * resolves to first, which is the address the loader pins, so a test proves
 * the loader dials the address it checked while the certificate is still
 * verified against the name the URL carried. Which loopback address comes
 * first is the host's choice: `::1` where the resolver lists IPv6 first.
 */

import { lookup } from 'node:dns/promises';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { TEST_TLS_CERT, TEST_TLS_KEY } from './tls-cert.js';

export type Handler = (request: IncomingMessage, response: ServerResponse) => void;

export interface TestServer {
  /** `https://localhost:<port>`, the origin a test should build URLs from. */
  origin: string;
  /** Every request the server received, in order. */
  requests: IncomingMessage[];
  close: () => Promise<void>;
}

export async function startTestServer(handler: Handler): Promise<TestServer> {
  const requests: IncomingMessage[] = [];
  const server = https.createServer({ key: TEST_TLS_KEY, cert: TEST_TLS_CERT }, (req, res) => {
    requests.push(req);
    handler(req, res);
  });
  const [first] = await lookup('localhost', { all: true });
  if (first === undefined) throw new Error('localhost did not resolve to any address');
  await new Promise<void>((resolve) => server.listen(0, first.address, resolve));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `https://localhost:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
