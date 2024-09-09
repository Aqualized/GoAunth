#Сгенерировал гпт чатом для удобства

FROM golang:1.23.0-alpine AS builder

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем файлы go.mod и go.sum
COPY go.mod go.sum ./
RUN go mod download

# Копируем весь проект
COPY . .

# Сборка приложения
RUN go build -o app ./cmd/TokenMain.go

# Минимальный образ для запуска
FROM alpine:latest

# Устанавливаем сертификаты
RUN apk --no-cache add ca-certificates

# Устанавливаем рабочую директорию
WORKDIR /root/

# Копируем скомпилированное приложение из предыдущего этапа
COPY --from=builder /app/app .

# Команда запуска приложения
CMD ["./app"]