import { useEffect, useRef, useState } from "react";
import { liveSocketUrl } from "./api";
import type { EventOut, LiveMessage } from "./types";

const MAX_EVENTS = 300;

/** WebSocket feed with backfill + auto-reconnect. Reconnect backs off so a
 * gateway restart doesn't turn into a hammering loop from every open tab. */
export function useLiveFeed() {
  const [events, setEvents] = useState<EventOut[]>([]);
  const [connected, setConnected] = useState(false);
  const [flash, setFlash] = useState<string | null>(null);
  const retryDelay = useRef(1000);

  useEffect(() => {
    let closed = false;
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;

    function connect() {
      ws = new WebSocket(liveSocketUrl());

      ws.onopen = () => {
        setConnected(true);
        retryDelay.current = 1000;
      };

      ws.onmessage = (raw) => {
        let msg: LiveMessage;
        try {
          msg = JSON.parse(raw.data);
        } catch {
          return;
        }
        if (msg.type === "heartbeat") return;
        if (msg.type === "backfill" && Array.isArray(msg.data)) {
          setEvents(msg.data.slice(-MAX_EVENTS));
          return;
        }
        if (!msg.data || Array.isArray(msg.data)) return;
        const event = msg.data;
        setEvents((prev) => {
          const idx = prev.findIndex((e) => e.id === event.id);
          if (idx === -1) return [...prev, event].slice(-MAX_EVENTS);
          const next = [...prev];
          next[idx] = event;
          return next;
        });
        if (msg.type === "event.created" || msg.type === "event.escalated") {
          setFlash(event.id);
          setTimeout(() => setFlash((f) => (f === event.id ? null : f)), 2500);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        if (closed) return;
        timer = setTimeout(connect, retryDelay.current);
        retryDelay.current = Math.min(retryDelay.current * 1.8, 20000);
      };

      ws.onerror = () => ws?.close();
    }

    connect();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, []);

  return { events, connected, flash };
}
