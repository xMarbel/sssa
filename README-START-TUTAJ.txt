VILO — projekt instalatora Windows

TO NIE JEST GOTOWY INSTALATOR. Ten ZIP zawiera kompletny projekt do zbudowania
pliku VILO-Setup-0.2.0.exe na komputerze Windows w GitHub Actions.

CO ZROBIC:
1. Utworz prywatne repozytorium na GitHub (nie udostepniaj w nim hasel).
2. Wgraj zawartosc tego archiwum jako pliki repozytorium (wraz z folderem .github).
3. GitHub > Actions > Buduj VILO dla Windows > Run workflow.
4. Po poprawnym zakonczeniu w zakladce Actions pobierz artefakt VILO-Windows-Setup.
5. Rozpakuj artefakt i sprawdz VILO-Setup-0.2.0.exe na Windows.

Instalator tworzy ikonke VILO i nie wymaga osobnego Pythona ani plikow .bat.
Aplikacja jest jednak nadal lokalna: backend dziala na 127.0.0.1.
Nie ma publicznego hostingu, rozmow glosowych, aplikacji mobilnych, ani wszystkich funkcji projektu.

UWAGA O BEZPIECZENSTWIE:
Plik .exe z automatycznego buildu jest NIEPODPISANY. Funkcja Inteligentna kontrola
aplikacji w Windows moze go nadal zablokowac. Nie wylaczaj zabezpieczen ani nie
obchodz ostrzezen. Publiczne wydanie wymaga weryfikacji kodu, bezpiecznego
hostingu i najlepiej podpisu cyfrowego.

Kod backendu pochodzi z poprzedniej lokalnej wersji testowej VILO.
Nie jest zaudytowany do publicznego udostepnienia w internecie.
