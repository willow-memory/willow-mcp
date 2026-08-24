"""
test_wake_gate.py — unit tests for the real WakeGate adapters (wake_gate.py).

Both OpenWakeWordGate and RealtimeSTTGate depend on native libraries (openwakeword,
numpy) that are not in the CI test matrix.  Tests mock the heavy imports and verify
the adapter wiring: correct args forwarded to the model, contract satisfied, errors
raised for bad input.

Run: pytest tests/test_wake_gate.py -v
"""
from __future__ import annotations

import sys
import unittest
from unittest.mock import MagicMock, patch

from willow_mcp.voice.voice_controller import Frame

_MOCK_NP = MagicMock()


def _make_gate_with_mock_model(cls):
    gate = cls.__new__(cls)
    gate._model = MagicMock()
    gate.threshold = 0.5
    gate.expected_frame_samples = 1280
    return gate


class TestOpenWakeWordGate(unittest.TestCase):
    def _make(self):
        from willow_mcp.voice.wake_gate import OpenWakeWordGate

        return _make_gate_with_mock_model(OpenWakeWordGate)

    @patch.dict(sys.modules, {"numpy": _MOCK_NP})
    def test_score_returns_max_prediction(self):
        gate = self._make()
        gate._model.predict.return_value = {"hey_willow": 0.3, "hey_jarvis": 0.8}
        frame = Frame(seq=1, pcm=b"\x00" * 2560)
        score = gate.score(frame)
        self.assertAlmostEqual(score, 0.8)

    @patch.dict(sys.modules, {"numpy": _MOCK_NP})
    def test_score_empty_preds_returns_zero(self):
        gate = self._make()
        gate._model.predict.return_value = {}
        frame = Frame(seq=1, pcm=b"\x00" * 2560)
        self.assertAlmostEqual(gate.score(frame), 0.0)

    @patch.dict(sys.modules, {"numpy": _MOCK_NP})
    def test_score_raises_on_missing_pcm(self):
        gate = self._make()
        frame = Frame(seq=1)
        with self.assertRaises(ValueError):
            gate.score(frame)

    def test_reset_delegates_to_model(self):
        gate = self._make()
        gate.reset()
        gate._model.reset.assert_called_once()


class TestRealtimeSTTGate(unittest.TestCase):
    def _make(self):
        from willow_mcp.voice.wake_gate import RealtimeSTTGate

        return _make_gate_with_mock_model(RealtimeSTTGate)

    @patch.dict(sys.modules, {"numpy": _MOCK_NP})
    def test_score_returns_max_prediction(self):
        gate = self._make()
        gate._model.predict.return_value = {"hey_willow": 0.92}
        frame = Frame(seq=1, pcm=b"\x00" * 2560)
        self.assertAlmostEqual(gate.score(frame), 0.92)

    @patch.dict(sys.modules, {"numpy": _MOCK_NP})
    def test_score_empty_preds_returns_zero(self):
        gate = self._make()
        gate._model.predict.return_value = {}
        frame = Frame(seq=1, pcm=b"\x00" * 2560)
        self.assertAlmostEqual(gate.score(frame), 0.0)

    @patch.dict(sys.modules, {"numpy": _MOCK_NP})
    def test_score_raises_on_missing_pcm(self):
        gate = self._make()
        frame = Frame(seq=1)
        with self.assertRaises(ValueError):
            gate.score(frame)

    def test_reset_delegates_to_model(self):
        gate = self._make()
        gate.reset()
        gate._model.reset.assert_called_once()

    def test_import_error_mentions_realtimestt(self):
        import importlib

        import willow_mcp.voice.wake_gate as mod

        saved = {}
        for name in list(sys.modules):
            if name == "openwakeword" or name.startswith("openwakeword."):
                saved[name] = sys.modules.pop(name)
        try:
            importlib.reload(mod)
            with patch.dict(sys.modules, {
                "openwakeword": None, "openwakeword.model": None,
            }):
                with self.assertRaises(ImportError) as ctx:
                    mod.RealtimeSTTGate()
                self.assertIn("RealtimeSTT", str(ctx.exception))
        finally:
            sys.modules.update(saved)
            importlib.reload(mod)

    def test_constructor_passes_wake_word_names(self):
        mock_model_cls = MagicMock()
        mock_oww = MagicMock()
        mock_oww_model = MagicMock(Model=mock_model_cls)
        with patch.dict(sys.modules, {
            "openwakeword": mock_oww,
            "openwakeword.model": mock_oww_model,
        }):
            import importlib

            import willow_mcp.voice.wake_gate as mod

            importlib.reload(mod)
            mod.RealtimeSTTGate(wake_words=("hey_willow", "hey_jarvis"))
            mock_model_cls.assert_called_once_with(
                wakeword_models=["hey_willow", "hey_jarvis"],
            )
        importlib.reload(mod)

    def test_satisfies_wake_gate_protocol(self):
        from willow_mcp.voice.voice_controller import WakeGate

        gate = self._make()
        self.assertIsInstance(gate, WakeGate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
