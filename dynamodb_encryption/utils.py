import json
from decimal import Decimal
from boto3.dynamodb.types import Binary


class DecimalEncoder(json.JSONEncoder):

    def default(self, o):
        if isinstance(o, Decimal):
            return float(o) if o % 1 != 0 else int(o)
        if isinstance(o, Binary):
            return str(o.value)
        return super(DecimalEncoder, self).default(o)


class Parser:

    @staticmethod
    def to_number(data):
        return json.loads(json.dumps(data, cls=DecimalEncoder))

    @staticmethod
    def to_decimal(data):
        return json.loads(json.dumps(data), parse_float=Decimal)
