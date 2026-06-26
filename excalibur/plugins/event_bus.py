import traceback


class EventBus:
    """Simple synchronous event bus for core and plugin events."""

    def __init__(self):
        self._subscribers = {}

    def subscribe(self, event_type, callback):
        self._subscribers.setdefault(event_type, []).append(callback)

    def emit(self, event):
        callbacks = list(self._subscribers.get(event.event_type, []))
        callbacks.extend(self._subscribers.get("*", []))
        for callback in callbacks:
            try:
                callback(event)
            except Exception as exc:
                callback_name = getattr(callback, "__name__", callback.__class__.__name__)
                print(
                    f"[PLUGIN] Event handler '{callback_name}' failed for {event.event_type}: {exc}",
                    flush=True,
                )
                traceback.print_exc()

