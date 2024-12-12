
from restfly.endpoint import APIEndpoint, APISession

class FindingsAPI(APIEndpoint):
    _path = 'asset/host/vm/detection/'
    
    def __init__(self, api: APISession):
        raise NotImplementedError()
    