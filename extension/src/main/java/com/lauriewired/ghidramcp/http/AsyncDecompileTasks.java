package com.lauriewired.ghidramcp.http;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.lauriewired.ghidramcp.core.GhidraAnalysisService;
import com.lauriewired.ghidramcp.core.McpException;
import com.lauriewired.ghidramcp.core.Model.Decompilation;
import com.lauriewired.ghidramcp.core.TriangrModel.AsyncTask;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Background decompilation, so a slow function does not hold the single request thread. Tasks
 * run on a bounded daemon pool; at most {@link #MAX_TASKS} are retained, and a result is
 * dropped once it has been read.
 */
final class AsyncDecompileTasks {

	static final int MAX_TASKS = 256;

	private static final String PENDING = "pending";
	private static final String RUNNING = "running";
	private static final String COMPLETED = "completed";
	private static final String FAILED = "failed";

	private static final class Task {
		final String id = UUID.randomUUID().toString();
		final String address;
		final long startMillis = System.currentTimeMillis();
		final TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		volatile long endMillis;
		volatile String status = PENDING;
		volatile Decompilation result;
		volatile String error;

		Task(String address) {
			this.address = address;
		}

		boolean finished() {
			return COMPLETED.equals(status) || FAILED.equals(status);
		}

		AsyncTask snapshot() {
			long end = endMillis > 0 ? endMillis : System.currentTimeMillis();
			return new AsyncTask(id, status, address, end - startMillis, error);
		}
	}

	private final GhidraAnalysisService service;
	private final Map<String, Task> tasks = new ConcurrentHashMap<>();
	private ExecutorService pool;

	AsyncDecompileTasks(GhidraAnalysisService service) {
		this.service = service;
	}

	synchronized void start() {
		if (pool != null && !pool.isShutdown()) {
			return;
		}
		AtomicInteger threads = new AtomicInteger();
		pool = Executors.newFixedThreadPool(Math.max(2, Runtime.getRuntime().availableProcessors()),
			r -> {
				Thread t = new Thread(r, "Triangr-Async-" + threads.incrementAndGet());
				t.setDaemon(true);
				return t;
			});
	}

	/** Cancels running tasks, stops the pool and forgets every task. */
	synchronized void stop() {
		if (pool == null) {
			return;
		}
		tasks.values().forEach(t -> t.monitor.cancel());
		pool.shutdownNow();
		try {
			pool.awaitTermination(2, TimeUnit.SECONDS);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		pool = null;
		tasks.clear();
	}

	synchronized boolean isHealthy() {
		return pool != null && !pool.isShutdown();
	}

	int size() {
		return tasks.size();
	}

	AsyncTask submit(Program program, String address, int timeoutSeconds) {
		// Fail fast on bad input instead of reporting it through the task.
		GhidraAnalysisService.functionAt(program, address);
		int timeout = GhidraAnalysisService.clampDecompileTimeout(timeoutSeconds);
		Task task = new Task(address);
		synchronized (this) {
			if (pool == null || pool.isShutdown()) {
				throw McpException.failed("The async decompilation pool is not running");
			}
			evictIfFull();
			tasks.put(task.id, task);
			pool.submit(() -> run(task, program, timeout));
		}
		return task.snapshot();
	}

	AsyncTask status(String taskId) {
		return find(taskId).snapshot();
	}

	/** Returns a completed task's decompilation and forgets the task. */
	Decompilation result(String taskId) {
		Task task = find(taskId);
		switch (task.status) {
			case COMPLETED:
				tasks.remove(taskId);
				return task.result;
			case FAILED:
				tasks.remove(taskId);
				throw new McpException("TASK_FAILED", 500,
					"Task " + taskId + " failed: " + task.error);
			default:
				throw new McpException("TASK_NOT_COMPLETE", 409, "Task " + taskId + " is " +
					task.status + "; poll get_task_status until it is completed");
		}
	}

	private void run(Task task, Program program, int timeout) {
		task.status = RUNNING;
		try {
			task.result = service.decompileByAddress(program, task.address, timeout, task.monitor);
			task.status = COMPLETED;
		}
		catch (McpException e) {
			task.error = "[" + e.code() + "] " + e.getMessage();
			task.status = FAILED;
		}
		catch (Throwable t) {
			task.error = t.getMessage() != null ? t.getMessage() : t.getClass().getName();
			task.status = FAILED;
		}
		finally {
			task.endMillis = System.currentTimeMillis();
		}
	}

	private Task find(String taskId) {
		Task task = tasks.get(taskId);
		if (task == null) {
			throw McpException.notFound("Task not found: " + taskId + ". Results are removed " +
				"once read, and at most " + MAX_TASKS + " tasks are kept.");
		}
		return task;
	}

	/** Makes room for one task, evicting the oldest finished task, else the oldest one. */
	private void evictIfFull() {
		while (tasks.size() >= MAX_TASKS) {
			Task oldestFinished = null;
			Task oldest = null;
			for (Task t : tasks.values()) {
				if (oldest == null || t.startMillis < oldest.startMillis) {
					oldest = t;
				}
				if (t.finished() &&
					(oldestFinished == null || t.startMillis < oldestFinished.startMillis)) {
					oldestFinished = t;
				}
			}
			Task victim = oldestFinished != null ? oldestFinished : oldest;
			if (victim == null) {
				return;
			}
			victim.monitor.cancel();
			tasks.remove(victim.id);
		}
	}
}
