from ip_extractor import IPAddressExtractor
from mid_extractor import MIDExtractor
from subject_extractor import SubjectExtractor
from loglevel_extractor import LoglevelExtractor
from date_extractor import DateExtractor
from time_extractor import TimeExtractor
from spam_res_extractor import SpamResExtractor
from attachment_extractor import AttachmentExtractor
from spam_engine_extractor import SpamEngineExtractor
from etk.extractors.date_extractor import DateExtractor as etk_date

from etk.etk import ETK
from etk.etk_module import ETKModule
from etk.document import Document
from etk.knowledge_graph_schema import KGSchema
from etk.utilities import Utility


import json, time


class RegexETKModule(ETKModule):
    """
    Abstract class for extraction module
    """

    def __init__(self, etk):
        ETKModule.__init__(self, etk)
        # bae = BitcoinAddressExtractor()
        # ce = CVEExtractor()
        # che = CryptographicHashExtractor()
        # he = HostnameExtractor()
        ip = IPAddressExtractor()
        mid = MIDExtractor()
        subject = SubjectExtractor()
        loglevel = LoglevelExtractor()
        date = DateExtractor()
        time = TimeExtractor()
        spam_engine = SpamEngineExtractor()
        spam_res = SpamResExtractor()
        attachment = AttachmentExtractor()
        self.date_extractor = etk_date(self.etk, 'log_date_parser')
        # ue = URLExtractor(True)
        self.e_list = [date, time ,ip, loglevel, mid, subject, spam_engine,spam_res, attachment]


    def process_document(self, doc):
        """
        Add your code for processing the document
        """

        # docs = json.load(open(doc.cdr_document['raw_content_path']))
        # print(docs)

        data = []
        newdocs = list()
        with open(doc.cdr_document.get("raw_content_path"), "r") as f_in:
            data = f_in.readlines()

        for log in data:
            final_res = []
            sample_input = {
                    "target_text": log.strip()
                }
            doc_sample = etk.create_document(sample_input)
            segment = doc_sample.select_segments("target_text")[0]
            # print(segment)
            for e in self.e_list:
                res = doc.extract(e, segment)
                final_res.append(res)
                # print(res)

            mid=''
            subject=''
            spam_res=''
            spam_engine=''
            attachment=''
            if final_res[4]:
                mid = final_res[4][0].value
            if final_res[5]:
                subject = final_res[5][0].value
            if final_res[6]:
                spam_engine = final_res[6][0].value
            if final_res[7]:
                spam_res = final_res[7][0].value
            if final_res[8]:
                attachment = final_res[8][0].value

            js = {'date':final_res[0][0].value,'time':final_res[1][0].value,'ip':final_res[2][0].value,
                  'log_level': final_res[3][0].value,'mid':mid,'subject':subject,'spam_engine':spam_engine,'spam_results':spam_res,'attachment':attachment}

            document = Document(self.etk, cdr_document=js, mime_type='json', url='')
            # document.doc_id = Utility.create_doc_id_from_json(document.cdr_document)
            document.kg.add_value('description', value=Utility.create_description_from_json(document.cdr_document))

            event_date = document.cdr_document.get('date', 0)
            if event_date != 0:
                date = event_date.split('.')
                extractables = self.date_extractor.extract('{}-{}-{}'.format(date[2], date[1], date[0]))
                # print(extractables)
                document.kg.add_value('event_date', value = extractables)

            document.kg.add_value('time', value=document.cdr_document.get("time"))
            document.kg.add_value('ip', value=document.cdr_document.get("ip"))
            document.kg.add_value('log_level', value=document.cdr_document.get("log_level"))
            if document.cdr_document.get('mid'):
                 document.kg.add_value('mid', value=document.cdr_document.get("mid"))
            if document.cdr_document.get('subject'):
                document.kg.add_value('subject', value=document.cdr_document.get("subject"))
            if document.cdr_document.get('spam_engine'):
                document.kg.add_value('spam_engine', value=document.cdr_document.get("spam_engine"))
            if document.cdr_document.get('spam_result'):
                document.kg.add_value('spam_result', value=document.cdr_document.get("spam_result"))
            if document.cdr_document.get('attachment'):
                document.kg.add_value('attachment', value=document.cdr_document.get("attachment"))
            newdocs.append(document)
            # print(js)

        return newdocs

        # print(data)

        # for line in f_in:
        #         sample_input = {
        #             "target_text": line.strip()
        #         }
        #         etk = ETK(modules=RegexETKModule, use_spacy_tokenizer=False)
        #         doc = etk.create_document(sample_input)
        #         docs = etk.process_ems(doc)
        #         # print(json.dumps(docs[0].value, indent=2))
        #         f.write((json.dumps(docs[0].value, indent=2))+"\n")
        # segment = doc.select_segments("target_text")[0]
        #
        # for e in self.e_list:
        #     res = doc.extract(e, segment)
        #     doc.store(res, e.name)
        # return list()
        # return newdocs

    def document_selector(self, doc: Document):
        """
         Boolean function for selecting document
         Args:
             doc: Document

         Returns:

        """
        return doc.cdr_document.get('dataset') == 'logs'


if __name__ == "__main__":

    f = open("res.txt", "w")
    #there's a parameter called load_spacy set this to false
    #https://github.com/fatestigma/etk/tree/kg_graph/examples/knowledge_graph (For knowledge graph output)
    js = dict()
    js['raw_content_path'] = "/Users/alhafni/Desktop/etk/effect/logs.txt"
    # js['raw_content_path'] = "/Users/alhafni/Desktop/ironport_logs/ironport.log.2018-08-20"
    js['dataset'] = "logs"

    kg_schema = KGSchema(json.load(open("/Users/alhafni/Desktop/etk/examples/knowledge_graph/master_config.json")))
    etk = ETK(modules=RegexETKModule, kg_schema=kg_schema)
    doc = Document(etk, cdr_document=js, mime_type='json',url='')
    results = etk.process_ems(doc)
    # print(results)
    for i in results:
         f.write(json.dumps(i.value, indent=4, sort_keys=True))
    # start = time.time()
    # with open("/Users/alhafni/Desktop/ironport_logs/ironport.log.2018-08-20", "r") as f_in:
    #     for line in f_in:
    #         sample_input = {
    #             "target_text": line.strip()
    #         }
    #         etk = ETK(modules=RegexETKModule, use_spacy_tokenizer=False)
    #         doc = etk.create_document(sample_input)
    #         docs = etk.process_ems(doc)
    #         # print(json.dumps(docs[0].value, indent=2))
    #         f.write((json.dumps(docs[0].value, indent=2))+"\n")
    # f.close()
    # print(time.time() - start)
