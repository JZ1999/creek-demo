from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr

from fama_interfaces.common import CommonBase, PositiveOrZeroInt32, str_1_255, str_255


class ActorsBase(BaseModel):
    name: str_1_255
    all_companies: Optional[bool] = False
    modified_by_id: PositiveOrZeroInt32 = PositiveOrZeroInt32(0)
    modified_by: Optional[UUID]
    is_user: bool


class Actors(ActorsBase, CommonBase):
    pass


class ActorCompaniesBase(BaseModel):
    actor_id: PositiveOrZeroInt32
    modified_by: Optional[UUID]
    company_uuid: UUID


class ActorCompanies(ActorCompaniesBase, CommonBase):
    pass


class ActorGroupsBase(BaseModel):
    name: str_1_255
    modified_by: Optional[UUID]


class ActorGroups(ActorGroupsBase, CommonBase):
    pass


class ActorGroupActorsBase(BaseModel):
    modified_by: Optional[UUID]
    actor_group_id: PositiveOrZeroInt32
    actor_id: PositiveOrZeroInt32


class ActorGroupActors(ActorGroupActorsBase, CommonBase):
    pass


class ActorGroupPermissionsBase(BaseModel):
    actor_group_id: PositiveOrZeroInt32
    modified_by_id: Optional[PositiveOrZeroInt32]
    modified_by: Optional[UUID]
    permission_type_id: PositiveOrZeroInt32


class ActorGroupPermissions(ActorGroupPermissionsBase, CommonBase):
    pass


class ActorMetricsBase(BaseModel):
    actor_id: PositiveOrZeroInt32
    name: str_1_255
    value: float
    modified_by_id: Optional[PositiveOrZeroInt32]
    modified_by: Optional[UUID]


class ActorMetrics(ActorMetricsBase, CommonBase):
    pass


class ActorPermissionsBase(BaseModel):
    actor_id: PositiveOrZeroInt32
    modified_by_id: Optional[PositiveOrZeroInt32]
    modified_by: Optional[UUID]
    permission_type_id: PositiveOrZeroInt32


class ActorPermissions(ActorPermissionsBase, CommonBase):
    pass


class PermissionTypesBase(BaseModel):
    name: str_1_255
    modified_by_id: Optional[PositiveOrZeroInt32]
    modified_by: Optional[UUID]


class PermissionTypes(PermissionTypesBase, CommonBase):
    pass


class ResponsibilitiesBase(BaseModel):
    user_id: PositiveOrZeroInt32
    modified_by: Optional[UUID]
    profile_confirm: bool
    post_scrape: bool
    post_rate: bool
    final_qa: bool


class Responsibilities(ResponsibilitiesBase, CommonBase):
    pass


class UsersBase(BaseModel):
    first_name: str_255
    last_name: str_255
    email: EmailStr
    is_active: bool
    actor_id: PositiveOrZeroInt32
    modified_by_id: Optional[PositiveOrZeroInt32]
    modified_by: Optional[UUID]


class Users(UsersBase, CommonBase):
    pass
