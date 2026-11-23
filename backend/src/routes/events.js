/**
 * GET /api/events - Server-Sent Events stream of live "alert", "block" and
 * "unblock" events, so the dashboard updates the instant Snort fires.
 */
const MAX_CLIENTS = 50;
const HEARTBEAT_MS = 25000;

module.exports = function eventsRoute({ events }) {
  let clients = 0;

  return (req, res) => {
    if (clients >= MAX_CLIENTS) return res.status(503).json({ error: 'Too many live connections' });
    clients++;
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write('retry: 3000\n\n');

    const unsubscribe = events.subscribe((type, payload) => {
      res.write(`event: ${type}\ndata: ${JSON.stringify(payload)}\n\n`);
    });
    const heartbeat = setInterval(() => res.write(': keep-alive\n\n'), HEARTBEAT_MS);

    req.on('close', () => {
      clients--;
      clearInterval(heartbeat);
      unsubscribe();
    });
    return undefined;
  };
};
