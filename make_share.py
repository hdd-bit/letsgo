# index.html을 고친 뒤 실행하면 share/index.html(이 기기에만 저장하는 학급 공유용)을 다시 만들어요.
h = open("index.html", encoding="utf-8").read()
s = h.replace('<script src="config.js"></script>', '<script>window.TAMHEOM_CONFIG = {sharePage:true, storageKey:"tamheom-share-v1"};</script>', 1)
s = s.replace("<title>탐험대 모둠 편성</title>", "<title>탐험대 모둠 편성 · 학급용</title>", 1)
open("share/index.html", "w", encoding="utf-8").write(s)
