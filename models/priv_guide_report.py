from pydantic import BaseModel, Field
from pathlib import Path
from typing import Any
import json

ExecutionStatus = int

class AttackNode(BaseModel):
    description: str
    query: str
    children: list["AttackNode"] = []
    execution_status: ExecutionStatus = Field(alias="execution status")
    execution_result: list[dict[str, Any]] | None = Field(alias="execution result", default=None)
    clearence_level: int = Field(alias="clearence level")
    groups: list[str] = []

class AttackTree(BaseModel):
    root: AttackNode

class ExtraData(BaseModel):
    location: str
    heading: str
    description: str
    data_row_line: str = Field(alias="data row line")
    results: list[dict[str, Any]] = []
    clearence_level: int = Field(alias="clearence level")
    groups: list[str] = []

class Requirement(BaseModel):
    title: str
    description: str
    results: list[dict[str, Any]] = []
    clearence_level: int | None = Field(alias="clearence level", default=None)
    groups: list[str] = []

class UserStory(BaseModel):
    use_case: str = Field(alias="use case")
    is_misuse_case: bool = Field(alias="is misuse case")
    requirements: list[Requirement] = []
    clearence_level: int = Field(alias="clearence level")
    groups: list[str] = []

class RuleResult(BaseModel):
    name: str
    description: str
    mapping_message: str = Field(alias="mapping message")
    is_consistency: bool = Field(alias="is consistency")
    violations: list[dict[str, Any]] = []
    maximum_violations: int = Field(alias="maximum violations")
    clearence_level: int = Field(alias="clearence level")
    groups: list[str] = []

class Regulation(BaseModel):
    name: str
    consistency_results: list[RuleResult] = Field(alias="consistency results", default=[])
    results: list[RuleResult] = []

class PrivGuideReport(BaseModel):
    branch: str
    time: int
    config: str
    project: str
    policies: list[Regulation] = []
    user_stories: list[UserStory] = Field(alias="user stories", default=[])
    extra_data: list[ExtraData] = Field(alias="extra data", default=[])
    attack_trees: list[AttackTree] = Field(alias="attack trees", default=[])

    @classmethod
    def from_str(cls, message: str) -> "PrivGuideReport | None":
        try:
            data = json.loads(message)
            return PrivGuideReport(**data)
        except:
            return None

    @classmethod
    def from_file_path(cls, str_path: str) -> "PrivGuideReport | None":
        try:
            with Path(str_path).open() as f:
                data = json.load(f)
                return PrivGuideReport(**data)
        except:
            return None
