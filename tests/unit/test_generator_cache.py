"""T5 provider cache keeps one model instance per effective configuration."""

from concurrent.futures import ThreadPoolExecutor

import pytest

import vuln2action.generation.base as generation_base
from vuln2action.config import GenerationSettings
from vuln2action.generation import clear_generator_cache, get_generator


@pytest.fixture(autouse=True)
def clean_cache():
    clear_generator_cache()
    yield
    clear_generator_cache()


def _settings(**overrides) -> GenerationSettings:
    return GenerationSettings.model_validate({"providers": {"t5": overrides}})


def test_t5_and_local_alias_share_one_instance():
    first = get_generator("t5")
    assert get_generator("t5") is first
    assert get_generator("local") is first


def test_different_checkpoint_or_device_uses_different_instance(monkeypatch):
    monkeypatch.setattr(generation_base, "load_model_settings", lambda: _settings(checkpoint="a"))
    first = get_generator("t5")
    monkeypatch.setattr(generation_base, "load_model_settings", lambda: _settings(checkpoint="b"))
    second = get_generator("t5")
    assert first is not second

    monkeypatch.setattr(
        generation_base,
        "load_model_settings",
        lambda: _settings(checkpoint="a", device="cuda"),
    )
    third = get_generator("t5")
    assert third is not first
    assert third is not second


def test_decoding_config_is_part_of_the_cache_key(monkeypatch):
    monkeypatch.setattr(generation_base, "load_model_settings", lambda: _settings(num_beams=2))
    first = get_generator("t5")
    monkeypatch.setattr(generation_base, "load_model_settings", lambda: _settings(num_beams=4))
    assert get_generator("t5") is not first


def test_clear_cache_forces_reload(monkeypatch):
    monkeypatch.setattr(generation_base, "load_model_settings", lambda: _settings())
    first = get_generator("t5")
    clear_generator_cache()
    assert get_generator("t5") is not first


def test_failed_config_does_not_poison_cache(monkeypatch):
    def boom():
        raise RuntimeError("bad config")

    monkeypatch.setattr(generation_base, "load_model_settings", boom)
    with pytest.raises(RuntimeError, match="bad config"):
        get_generator("t5")

    monkeypatch.setattr(generation_base, "load_model_settings", lambda: _settings())
    first = get_generator("t5")
    assert get_generator("t5") is first


def test_concurrent_requests_share_one_instance():
    with ThreadPoolExecutor(max_workers=8) as executor:
        generators = list(executor.map(lambda _: get_generator("t5"), range(16)))
    assert len({id(generator) for generator in generators}) == 1


def test_other_providers_keep_original_fresh_instance_behavior():
    assert get_generator("rule_based") is not get_generator("rule_based")
    assert get_generator("llm") is not get_generator("llm")
