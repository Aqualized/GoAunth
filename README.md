# GoAunth
## Часть сервиса аунтефекации

### **Запуск на вашем апаратике:**
Необходимо иметь Docker

1) клоним гит
2) в терминале 
  docker-compose --env-file .env up --build
3) ну и пишем запросики(к сожалению пока что без тестов)
4) ну вод сгенерированный случайно guid для запроса как пример

7a1a6b41-46cd-4e6f-b668-020e1922d93e
Запрашиваем впервые токены:  http://localhost:8000/auth?guid=7a1a6b41-46cd-4e6f-b668-020e1922d93e
берем врученные токены и отправляем: http://localhost:8000/auth/refresh
с хедерами:
  **Authorization**:  Bearer **ваш-аксес-токен**
  **Refresh-Token**:  **рефрешТокен**

Планы на развитие:
[x] базовая работоспособность
[x]  базовая валидация
[] Тестирование
[] Улучшение докера
[] Углубление в Ip и валидацию запросов, чтобы все детали были проверены
[] доделование до v1.0
