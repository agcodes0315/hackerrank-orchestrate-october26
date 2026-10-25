import unittest
from engine import deletion_intent

class IntentExpansionTests(unittest.TestCase):
    def test_english_explicit(self):
        for t in ('I would like the account associated with this address to be erased.',
                  'I no longer use this account and would like it permanently deleted.',
                  'Please remove my profile and clean my personal details out of messages.',
                  'I am asking you to remove my account and the personal information linked to it.'):
            with self.subTest(text=t): self.assertIs(deletion_intent(t), True)

    def test_multilingual_explicit(self):
        for t in ('Solicito la eliminación permanente de la cuenta asociada a este correo',
                  'Solicito a exclusão permanente da conta associada a este e-mail',
                  'Je demande la suppression définitive du compte associé à cette adresse e-mail',
                  'このメールアドレスに関連するアカウントの完全な削除を依頼します。',
                  '이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다'):
            with self.subTest(text=t): self.assertIs(deletion_intent(t), True)

    def test_negation_preserved(self):
        self.assertIs(deletion_intent('Please do not delete my account.'), False)
        self.assertIs(deletion_intent('Please remove me from marketing lists only.'), None)
        self.assertIs(deletion_intent('Can you verify that my account was deleted?'), None)
        self.assertIs(deletion_intent('Help with my account'), None)
