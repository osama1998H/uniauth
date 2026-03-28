package service

import "log/slog"

type asyncDispatcher[T any] struct {
	name   string
	logger *slog.Logger
	tasks  chan T
}

func newAsyncDispatcher[T any](name string, logger *slog.Logger, buffer, workers int, handler func(T)) *asyncDispatcher[T] {
	if buffer <= 0 {
		buffer = 1
	}
	if workers <= 0 {
		workers = 1
	}

	dispatcher := &asyncDispatcher[T]{
		name:   name,
		logger: logger,
		tasks:  make(chan T, buffer),
	}

	for i := 0; i < workers; i++ {
		go func() {
			for task := range dispatcher.tasks {
				handler(task)
			}
		}()
	}

	return dispatcher
}

func (d *asyncDispatcher[T]) Enqueue(task T) {
	if d == nil {
		return
	}

	select {
	case d.tasks <- task:
	default:
		if d.logger != nil {
			d.logger.Warn("async dispatcher queue full", "dispatcher", d.name, "capacity", cap(d.tasks))
		}
	}
}
