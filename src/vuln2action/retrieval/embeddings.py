"""Optional embedding backend contract."""


class EmbeddingRetriever:
    def __init__(self, model_name: str = "") -> None:
        self.model_name = model_name

    def search(self, query: str, documents: list[str], top_k: int = 3) -> list[tuple[int, float]]:
        raise NotImplementedError(
            "Embedding retrieval is not configured. Use keyword or TF-IDF until an "
            "evaluated embedding backend is added."
        )
