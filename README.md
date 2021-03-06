Постановка задачи
Разработать клиент-серверное приложение, реализующую алгоритм авторизации без передачи пароля - SRP.
Ход выполнения работы
1) Клиент
1.1) Клиентское приложение состоит из двух окон – регистрация и авторизация. При регистрации клиент высчитывает соль и верификатор. 
1.2) При авторизации вычисляет ключи (A, a) . Далее, начинается обмен данными с сервером и вычисления, необходимые для подтверждения. Последним этапом является вычисление подтверждения M, отправка его на сервер, получение от сервера подтверждения R и сравнивание результатов.
2) Сервер
2.1) Сервер заносит в список пользователей нового пользователя и производит аутентификацию, после чего происходят необходимые вычисления и обмен данными с клиентом. В конце сервер получает от клиента подтверждение M, сравнивание, вычисление подтверждения R и отправляет его клиенту.
Вывод
Разработано клиент-серверное приложение, реализующее алгоритм авторизации без передачи пароля - SRP. Программа работает корректно:
- при регистрации все пользователи заносятся в список без потерь;
- при попытке зарегистрировать пользователя с существующим именем, сервер присылает сообщение о существовании такого пользователя;
- при попытке зайти под несуществующим именем пользователя, сервер присылает соответствующее сообщение об ошибке аутентификации;
- при попытке зайти с неправильным паролем, сервер присылает соответствующее сообщение о неправильности пароля;
- при корректно введенной паре логин-пароль выводится сообщение об успешном входе.
