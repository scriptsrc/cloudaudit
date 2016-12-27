# from cloudaux.orchestration.aws.iam.user import fields
import json
import boto3


class BaseCheck:
    default_score = 0
    _id = None

    def __init__(self, has_issue=False, notes=None):
        self.has_issue = has_issue or bool(notes)
        self.notes = notes
    
    @classmethod
    def id(cls):
        return cls._id or cls.__name__

    @classmethod
    def from_notes(cls, notes, has_issue=False):
        return cls(has_issue=has_issue, notes=notes)

    def __nonzero__(self):
        """ doesn't seem to fire in python3 """
        print('nonzero - hasissue: {}'.format(self.has_issue))
        return self.has_issue  # or bool(self.notes)

    def __str__(self):
        notes = ''
        if self.notes:
            notes = "\n\tNotes: {notes}".format(notes=json.dumps(self.notes))
        return "<Item Issue ID: {id}\n\tText: {text}\n\tDefault Score: {default_score}{notes}>".format(
                id=self.id(), text=self.text, default_score=self.default_score, notes=notes)

    def __repr__(self):
        return self.__str__()

    def to_compliance_format(self):
        compliance = 'COMPLIANT'
        if self:
            compliance = 'NON_COMPLIANT'
        return dict(
            Annotation=self.text,
            ComplianceType=compliance
            # COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE
        )


class CheckActiveAccessKeys(BaseCheck):
    _id = '28c0fd9a-d92a-4cdb-bef9-19c4b6657721'
    config_resources = {'AWS::IAM::User'}
    text = 'IAM User has an active access key.'
    default_score = 1

    # @staticmethod
    # def fields():
    #     return [fields.ACCESS_KEYS]

    @classmethod
    def check(cls, item):
        """
        alert when an IAM User has an active access key.
        """
        notes = []
        akeys = item.get('AccessKeys', [])
        for akey in akeys:
            if 'Status' in akey and akey['Status'] == 'Active':
                notes.append(akey['AccessKeyId'])
        return cls.from_notes(notes)


class CheckInActiveAccessKeys(BaseCheck):
    _id = '9e274ff5-835a-4c1e-ac57-6732516314e4'
    config_resources = {'AWS::IAM::User'}
    text = 'IAM User has an inactive access key.'

    # @staticmethod
    # def fields():
    #     return [fields.ACCESS_KEYS]

    @classmethod
    def check(cls, item):
        """
        alert when an IAM User has an inactive access key.
        """
        notes = []
        akeys = item.get('AccessKeys', [])
        for akey in akeys:
            if 'Status' in akey and akey['Status'] != 'Active':
                pass
                # notes.append(akey['AccessKeyId'])
        return cls.from_notes(notes, has_issue=False)


def load_checks(config_resource_type=None):
    """ scope issues prevent this method from working. """
    checks = [getattr(__import__('iam_user'), check) for check in dir() if check.startswith('Check')]

    if config_resource_type:
        checks = [check for check in checks if config_resource_type in check.config_resources]
    
    return checks


def get_item(resource_type, resource_id, fields=None, config=None):
    """
    Can either grab data from config or (more likely)
    wire up to cloudaux to get the data we need.
    """
    config = config or boto3.client("config")
    resource_information = config.get_resource_config_history(
        resourceType=resource_type,
        resourceId=resource_id)
    # user_name = resource_information["configurationItems"][0]["resourceName"]
    return resource_information["configurationItems"][0]


def lambda_handler(event, context):
    config = boto3.client("config")

    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]
    config_resource_type = configuration_item["resourceType"]
    config_resource_id = configuration_item["resourceId"]
    timestamp = configuration_item["configurationItemCaptureTime"]

    checks = load_checks(config_resource_type=config_resource_type)
    fields = {check.fields for check in checks}
    item = get_item(config_resource_type, config_resource_id, fields=fields, config=config)

    item_issues = [check.check(item) for check in checks]
    evaluations = []
    for issue in item_issues:
        evaluation = dict(
            ComplianceResourceType=config_resource_type,
            ComplianceResourceId=config_resource_id,
            OrderingTimestamp=timestamp
        )
        evaluation.update(issue.to_compliance_format())
        evaluations.add(evaluation)

    config.put_evaluations(
        Evaluations=evaluations,
        ResultToken=event.get('resultToken', 'No token found.')
    )


if __name__ == '__main__':

    item = dict(
        AccessKeys=[
            dict(
                Status='Active',
                AccessKeyId='12345'
            ),
            dict(
                Status='Active',
                AccessKeyId='5678'
            ),
            dict(
                Status='InActive',
                AccessKeyId='9012'
            )
        ])

    checks = load_checks(config_resource_type='AWS::IAM::User')
    print('Checks: {}'.format(checks))

    item_issues = [check.check(item) for check in checks]
    for issue in item_issues:
        if issue:
            print(issue)
            # print(issue.to_compliance_format())


# Todo:
#X  set issue to true but with an empty notes list?
#  optionally work with config rules.
#X       - Must return Compliance format json
#X       - must check/define APPLICABLE_RESOURCES 
#X       - need lambda handler (only fires enabled rules)
#X       - need to gather relevant fields from cloudaux