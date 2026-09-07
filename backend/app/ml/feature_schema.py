from app.core.constants import FEATURE_COLUMNS


class FeatureSchema:
    def __init__(self, columns: list[str] | None = None) -> None:
        self.columns = list(columns or FEATURE_COLUMNS)
        self._index = {name: i for i, name in enumerate(self.columns)}

    def vectorize(self, features: dict) -> list[float]:
        vector: list[float] = []
        for column in self.columns:
            value = features.get(column, 0.0)
            try:
                vector.append(float(value))
            except (TypeError, ValueError):
                vector.append(0.0)
        return vector

    def devectorize(self, vector: list[float]) -> dict:
        return {column: vector[i] for i, column in enumerate(self.columns) if i < len(vector)}

    def validate(self, vector: list[float]) -> bool:
        return len(vector) == len(self.columns)

    def to_json(self) -> dict:
        return {"columns": self.columns}

    @classmethod
    def from_json(cls, data: dict) -> "FeatureSchema":
        return cls(columns=data.get("columns"))


DEFAULT_SCHEMA = FeatureSchema()