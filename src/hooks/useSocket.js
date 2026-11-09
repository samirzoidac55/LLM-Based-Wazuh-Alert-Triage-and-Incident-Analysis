import { useCallback, useEffect, useReducer, useRef } from "react";

const MAX_ALERTS = 500;
const MAX_RETRY_DELAY = 15_000;

const initial = {
  status: "idle", // idle | connecting | open | reconnecting
  alerts: [],     // newest first
  reports: [],    // batch incident reports, newest first
  server: null,   // { model, block_level, min_level } from the bridge's hello
  attempt: 0,
  error: "",
};

const byNewest = (a, b) => (a.received_at < b.received_at ? 1 : -1);

function reducer(state, action) {
  switch (action.type) {
    case "connecting":
      return { ...state, status: "connecting", error: "" };
    case "open":
      return { ...state, status: "open", attempt: 0, error: "" };
    case "closed":
      return { ...state, status: action.retrying ? "reconnecting" : "idle", attempt: action.attempt ?? 0 };
    case "error":
      return { ...state, error: action.error };
    case "hello":
      return { ...state, server: action.server };
    case "history": {
      // Replay from the bridge — merge by id so a reconnect fills gaps without duplicates.
      const known = new Set(state.alerts.map((a) => a.id));
      const fresh = action.alerts.filter((a) => !known.has(a.id));
      return { ...state, alerts: [...fresh, ...state.alerts].sort(byNewest).slice(0, MAX_ALERTS) };
    }
    case "alert":
      return { ...state, alerts: [action.alert, ...state.alerts].slice(0, MAX_ALERTS) };
    case "analysis":
      return {
        ...state,
        alerts: state.alerts.map((a) =>
          a.id === action.id
            ? {
                ...a,
                analysis_status: action.status,
                analysis: action.analysis ?? a.analysis,
                analysis_ms: action.analysis_ms,
                analysis_error: action.error,
              }
            : a
        ),
      };
    case "batch_analysis":
      return { ...state, reports: [action.report, ...state.reports].slice(0, 10) };
    case "clear":
      return { ...state, alerts: [], reports: [] };
    default:
      return state;
  }
}

/**
 * WebSocket connection to the Python bridge with automatic reconnect
 * (exponential backoff, capped at 15s). Reconnects only while the user
 * wants a connection — a manual disconnect stays disconnected.
 */
export function useSocket() {
  const [state, dispatch] = useReducer(reducer, initial);
  const wsRef = useRef(null);
  const intentRef = useRef(false);
  const attemptRef = useRef(0);
  const retryTimerRef = useRef(null);
  const urlRef = useRef("");
  // Lets the reconnect timer call the latest `open` without a self-reference.
  const openRef = useRef(() => {});

  const open = useCallback(() => {
    dispatch({ type: "connecting" });
    let ws;
    try {
      ws = new WebSocket(urlRef.current);
    } catch (err) {
      dispatch({ type: "error", error: `WebSocket error: ${err.message}` });
      dispatch({ type: "closed", retrying: false });
      intentRef.current = false;
      return;
    }
    wsRef.current = ws;

    ws.onopen = () => {
      attemptRef.current = 0;
      dispatch({ type: "open" });
    };

    ws.onmessage = (e) => {
      let msg;
      try {
        msg = JSON.parse(e.data);
      } catch {
        dispatch({ type: "error", error: "Received malformed JSON from the bridge." });
        return;
      }
      if (msg.type === "hello") dispatch({ type: "hello", server: msg });
      else if (msg.type === "history") dispatch({ type: "history", alerts: msg.alerts ?? [] });
      else if (msg.type === "alert") dispatch({ type: "alert", alert: msg.alert });
      else if (msg.type === "analysis") dispatch({ type: "analysis", ...msg });
      else if (msg.type === "batch_analysis") dispatch({ type: "batch_analysis", report: msg });
    };

    ws.onerror = () => {
      dispatch({ type: "error", error: `Could not reach ${urlRef.current} — is the Python bridge running?` });
    };

    ws.onclose = () => {
      wsRef.current = null;
      if (!intentRef.current) {
        dispatch({ type: "closed", retrying: false });
        return;
      }
      const attempt = ++attemptRef.current;
      const delay = Math.min(MAX_RETRY_DELAY, 1000 * 2 ** (attempt - 1));
      dispatch({ type: "closed", retrying: true, attempt });
      retryTimerRef.current = setTimeout(() => openRef.current(), delay);
    };
  }, []);

  useEffect(() => {
    openRef.current = open;
  }, [open]);

  const connect = useCallback(
    (host, port) => {
      clearTimeout(retryTimerRef.current);
      urlRef.current = `ws://${host}:${port}`;
      intentRef.current = true;
      attemptRef.current = 0;
      open();
    },
    [open]
  );

  const disconnect = useCallback(() => {
    intentRef.current = false;
    clearTimeout(retryTimerRef.current);
    wsRef.current?.close();
    dispatch({ type: "closed", retrying: false });
  }, []);

  const clearAlerts = useCallback(() => dispatch({ type: "clear" }), []);

  useEffect(
    () => () => {
      intentRef.current = false;
      clearTimeout(retryTimerRef.current);
      wsRef.current?.close();
    },
    []
  );

  return { ...state, connect, disconnect, clearAlerts };
}
