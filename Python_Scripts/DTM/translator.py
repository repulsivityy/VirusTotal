from googletrans import Translator

def translate_text(text, dest_langs):
  """
  Translates text to multiple languages using the Google Translate API.

  Args:
    text: The text to translate.
    dest_langs: A list of destination language codes (e.g., ['fr', 'es', 'ja']).

  Returns:
    A dictionary where keys are language codes and values are the translated text.
  """
  translator = Translator()
  translations = {}
  for lang in dest_langs:
    translated = translator.translate(text, dest=lang)
    translations[lang] = translated.text
  return translations

if __name__ == "__main__":
  text_to_translate = input("Enter the text you want to translate: ")
  print("A list of lanague codes can be found here - https://developers.google.com/admin-sdk/directory/v1/languages")
  target_languages = input("Enter the target language codes separated by commas (e.g., 'fr,es,ja'): ")
  target_languages_list = [lang.strip() for lang in target_languages.split(',')]

  translated_texts = translate_text(text_to_translate, target_languages_list)
  for lang, translation in translated_texts.items():
    print(f"{lang}: {translation}")