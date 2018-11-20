from etk.extractors.regex_extractor import RegexExtractor


class SubjectExtractor(RegexExtractor):
    """
    **Description**
           This class inherits RegexExtractor and predefines the ip address pattern

    Examples:
        ::

            ip_address_extractor = IPAddressExtractor()
            ip_address_extractor.extract(text=input_doc)
    """
    def __init__(self):
        subject_pattern = '(?:.+?(?=Subject))?Subject\s((.*)?)'
        RegexExtractor.__init__(self, pattern=subject_pattern, extractor_name="Subject")




#
# (?<date>[\d\.]+)\;(?<time>[\d\:]+)(?:.*)\;(?<log>[\w]+)\;(?<loglevel>[\w]+)(?:.+?(?<=MID))?(?<MID>(\s\d+)?)(?:.+?(?=CASE))?CASE\s[\w]+\s(?<spam result>([\w]+)?)
#


