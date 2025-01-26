import os
from typing import Annotated
from fastapi import Depends
import common.config as conf

class IdentityRegistryConfig(conf.Config):
    def __init__(self):
        super().__init__()
        self.app_name = os.getenv("APP_NAME", "Identity Registry")

inject = Annotated[IdentityRegistryConfig, Depends(IdentityRegistryConfig)]