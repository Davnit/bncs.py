
from asyncio import Queue, sleep
import time


class CreditQueue(Queue):
    START_CREDITS = 200             # Credits at start
    MAX_CREDITS = 600               # Maximum credits
    CREDIT_RATE = 7                 # Milliseconds required to earn 1 credit
    BYTE_COST = 7                   # Cost per byte of a message
    PENALTY_THRESHOLD = 200         # Max number of bytes for base credit cost
    PENALTY_COST = 8                # Cost per byte of a message longer than the PENALTY_THRESHOLD
    MESSAGE_COST = 200              # Cost per message

    def __init__(self, maxsize=0):
        super().__init__(maxsize)
        self.credits = self.START_CREDITS       # Number of credits available as of the last update
        self.last_update = 0                    # Tick value at the last update
        self.queued_cost = 0                    # Credit value of items currently in queue.

    def calculate_time_to_empty(self):
        """Returns the minimum number of fractional seconds until the queue could be emptied."""
        self.update()
        total_credits = self.credits - self.queued_cost
        return (total_credits * self.CREDIT_RATE) / 1000

    def calculate_cost(self, item):
        """Returns the credit cost of the given message item."""
        byte_cost = self.PENALTY_COST if len(item) > self.PENALTY_THRESHOLD else self.BYTE_COST
        return self.MESSAGE_COST + (byte_cost * len(item))

    def update(self):
        """Updates the credit counter to include credits accumulated since the last update."""
        elapsed_ms = ((time.monotonic() - self.last_update) * 1000)
        self.credits = min(elapsed_ms * self.CREDIT_RATE, self.MAX_CREDITS)
        self.last_update = time.monotonic()

    def pad(self, item):
        """Charges an item against the queue's available credits without adding it."""
        self.update()
        self.credits -= self.calculate_cost(item)

    def refund(self, item):
        """Adds the cost of an item back onto the available credits.
            Should only be called with a previously-removed item that was NOT SENT."""
        self.update()
        self.credits += self.calculate_cost(item)

    async def get(self):
        """Removes an item from the queue and returns it once enough credits are available."""
        item = await super().get()
        cost = self.calculate_cost(item)

        self.update()
        if cost > self.credits:
            needed_credits = cost - self.credits
            await sleep((needed_credits * self.CREDIT_RATE) / 1000)

        self.queued_cost -= cost
        self.credits -= cost
        return item

    def get_nowait(self):
        """Returns an item immediately regardless of the available number of credits."""
        item = super().get_nowait()
        cost = self.calculate_cost(item)
        self.update()
        self.queued_cost -= cost
        self.credits -= cost

    async def put(self, item):
        """Puts an item into the queue once space is available."""
        await super().put(item)
        self.queued_cost += self.calculate_cost(item)

    def put_nowait(self, item):
        """Puts an item into the queue immediately, if space is available."""
        super().put_nowait(item)
        self.queued_cost += self.calculate_cost(item)

    def task_done(self):
        """Signals that a removed item has been sent."""
        self.update()
        super().task_done()

    def clear(self):
        """Removes all items from the queue immediately and returns them."""
        items = []
        while not super().empty():
            items.append(super().get_nowait())

        self.queued_cost = 0
        self.update()
        return items
