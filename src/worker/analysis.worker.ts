import { handleRequest } from './handler';

/**
 * Web Worker entry point. Parsing and analysis run here, off the main thread,
 * so a hostile or enormous message cannot freeze the page, and the worker can
 * be terminated (freeing all of its memory) as soon as a result is delivered.
 * This worker contains no network code and loads no further scripts.
 */

// The app is compiled with the DOM library; declaring only the worker members
// used here avoids mixing the conflicting WebWorker library into the program.
interface WorkerScope {
  onmessage: ((event: MessageEvent<unknown>) => void) | null;
  postMessage(message: unknown, transfer: Transferable[]): void;
}

const scope = self as unknown as WorkerScope;

scope.onmessage = (event) => {
  void handleRequest(event.data, (message, transfer = []) => scope.postMessage(message, transfer));
};
