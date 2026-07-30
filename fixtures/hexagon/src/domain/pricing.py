# Fixture: domain logic that reaches outside the hexagon and dispatches on type.
# Fires architecture:framework-in-domain (requests), smells:type-check-chain
# (three isinstance tests on one ladder) and smells:service-locator
# (a dependency fetched from a global instead of injected).
import requests


def describe(shape):
    if isinstance(shape, Circle):
        return "circle"
    elif isinstance(shape, Square):
        return "square"
    elif isinstance(shape, Triangle):
        return "triangle"
    return "unknown"


def rate_for(currency):
    rates = RateRegistry.get_instance()
    return rates.lookup(currency)


def fetch_published_rate(currency):
    return requests.get("https://rates.example/" + currency).json()
