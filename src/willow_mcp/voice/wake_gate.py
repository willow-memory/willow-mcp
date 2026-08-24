"""
wake_gate.py — real WakeGate adapters for the voice ingress membrane (Step 2 drop-in).

The pure-script core (voice_controller.py) owns the WakeGate *contract* and a synthetic
StubWakeGate. This module holds the REAL engine adapters. Their heavy dependencies
(openwakeword, numpy) are imported lazily inside the constructor / call, so importing
this module stays dependency-free — only *constructing* an adapter pulls the deps in.

Wiring (Step 2), once the capture loop from the in-tree voice_mode.py fills frame.pcm
with raw int16 audio:

    from willow_mcp.voice.voice_controller import VoiceController
    from willow_mcp.voice.wake_gate import OpenWakeWordGate
    gate = OpenWakeWordGate(model_paths=["hey_willow.tflite"])
    controller = VoiceController(wake_gate=gate, vad_fn=..., transcribe_fn=..., ...)

Nothing else changes: the controller treats the wake score as an opaque number and
already resets the gate on every return to IDLE — exactly openWakeWord's lifecycle.

Design: willow/design/willow-voice-ingress-membrane.md · ΔΣ=42
"""
from __future__ import annotations

from typing import Sequence

from willow_mcp.voice.voice_controller import Frame


class OpenWakeWordGate:
    """Drop-in WakeGate backed by dscripka/openWakeWord (open models, no API key).

    openWakeWord is streaming and stateful: predict() consumes ~80 ms of 16 kHz int16
    audio (1280 samples) per call and returns {model_name: score}. The controller feeds
    it ONLY while IDLE and calls reset() on every return to IDLE — the ring buffer must be
    cleared between activations or a stale partial keeps the score hot. That lifecycle is
    already guaranteed by VoiceController; this adapter just satisfies the contract.
    """

    def __init__(
        self,
        model_paths: Sequence[str],
        *,
        threshold: float = 0.5,
        expected_frame_samples: int = 1280,
    ):
        from openwakeword.model import Model  # lazy: only needed when actually constructed

        self._model = Model(wakeword_models=list(model_paths))
        self.threshold = threshold
        self.expected_frame_samples = expected_frame_samples

    def score(self, frame: Frame) -> float:
        import numpy as np

        if frame.pcm is None:
            raise ValueError("OpenWakeWordGate needs frame.pcm (raw int16 audio)")
        samples = np.frombuffer(frame.pcm, dtype=np.int16)
        preds = self._model.predict(samples)
        return max(preds.values()) if preds else 0.0

    def reset(self) -> None:
        self._model.reset()


class RealtimeSTTGate:
    """Fallback WakeGate backed by RealtimeSTT's bundled openwakeword.

    ``pip install RealtimeSTT`` brings openwakeword, Silero VAD, and faster-whisper
    in one install. This gate uses the openwakeword scorer for the same frame-by-frame
    WakeGate contract as OpenWakeWordGate; the controller does not change.

    Constructor takes wake word NAMES (``("hey_willow",)``) that openwakeword resolves
    to its bundled models, rather than explicit model file paths.
    """

    def __init__(
        self,
        wake_words: Sequence[str] = ("hey_willow",),
        *,
        threshold: float = 0.5,
        expected_frame_samples: int = 1280,
    ):
        try:
            from openwakeword.model import Model
        except ImportError:
            raise ImportError(
                "RealtimeSTTGate needs openwakeword (bundled with RealtimeSTT). "
                "Install: pip install RealtimeSTT   (or: pip install openwakeword)"
            ) from None
        self._model = Model(wakeword_models=list(wake_words))
        self.threshold = threshold
        self.expected_frame_samples = expected_frame_samples

    def score(self, frame: Frame) -> float:
        import numpy as np

        if frame.pcm is None:
            raise ValueError("RealtimeSTTGate needs frame.pcm (raw int16 audio)")
        samples = np.frombuffer(frame.pcm, dtype=np.int16)
        preds = self._model.predict(samples)
        return max(preds.values()) if preds else 0.0

    def reset(self) -> None:
        self._model.reset()
