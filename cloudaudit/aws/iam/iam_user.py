# from cloudaux.orchestration.aws.iam.user import fields
import json


class BaseCheck:
    default_score = 0
    
    def __init__(self, notes=None):
        self.notes = notes
    
    @classmethod
    def from_notes(cls, notes):
        return cls(notes=notes)
    
    def __nonzero__(self):
        return bool(self.notes)
    
    def __str__(self):
        return "<Item Issue ID: {id}\n\tText: {text}\n\tDefault Score: {default_score}\n\tNotes: {notes}>".format(
                id=self.id, text=self.text, default_score=self.default_score, notes=json.dumps(self.notes))

    def __repr__(self):
        return self.__str__()


class CheckActiveAccessKeys(BaseCheck):
    id = '28c0fd9a-d92a-4cdb-bef9-19c4b6657721'
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
    id = '9e274ff5-835a-4c1e-ac57-6732516314e4'
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
                notes.append(akey['AccessKeyId'])
        return cls.from_notes(notes)


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
        
    checks = [getattr(__import__('iam_user'), check) for check in dir() if check.startswith('Check')]

    item_issues = [check.check(item) for check in checks]
    for issue in item_issues:
        if issue:
            print issue
