import unittest
from rag.ratelimit import Limiter, DailyCap


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class LimiterTest(unittest.TestCase):
    def test_minute_window(self):
        c = Clock()
        lim = Limiter(3, clock=c)
        self.assertEqual([lim.allow("a") for _ in range(4)], [True, True, True, False])
        self.assertTrue(lim.allow("b"))
        c.t += 61
        self.assertTrue(lim.allow("a"))

    def test_daily_caps(self):
        c = Clock(86400 * 100 + 10)
        cap = DailyCap(per_key=2, global_cap=3, clock=c)
        self.assertIsNone(cap.take("ip1"))
        self.assertIsNone(cap.take("ip1"))
        self.assertIn("daily limit", cap.take("ip1"))
        self.assertIsNone(cap.take("ip2"))
        self.assertIn("global", cap.take("ip3"))
        self.assertEqual(cap.remaining("ip1"), 0)
        c.t += 86400
        self.assertIsNone(cap.take("ip1"))
        self.assertEqual(cap.remaining("ip9"), 2)


if __name__ == "__main__":
    unittest.main()
