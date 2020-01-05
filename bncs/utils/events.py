
class EventDispatcher:
    """Dispatches events to registered listeners with prioritization."""
    def __init__(self):
        self._listeners = {}

    def add_listener(self, callback, event=None, priority=0):
        """Registers a callback for an event.

        callback: function to execute when the event is raised
        event: name of the event to listen for (default uses name of the callback)
        priority: order of execution - higher values go first (default 0)
        """
        if not event:
            event = callback.__name__
            if event.startswith("on_"):
                event = event[3:]

        if event not in self._listeners:
            self._listeners[event] = {}

        if priority not in self._listeners[event]:
            self._listeners[event][priority] = [callback]
        else:
            self._listeners[event][priority].append(callback)

    def remove_listener(self, callback, event=None):
        """Unregisters a callback for an event.

        callback: function to remove
        event: name of the event the function is registered to (default uses name of the callback)
        """
        if not event:
            event = callback.__name__
            if event.startswith("on_"):
                event = event[3:]

        if event in self._listeners:
            for priority in self._listeners[event].keys():
                if callback in self._listeners[event][priority]:
                    self._listeners[event][priority].remove(callback)

    def dispatch(self, event, *args):
        """Raises an event to listeners.

        event: name of the event to raise
        args: arguments associated with the event
        """
        event = 'on_' + event

        if event in self._listeners:
            for priority in sorted(self._listeners[event].keys(), reverse=True):
                for listener in self._listeners[event][priority]:
                    listener(*args)
