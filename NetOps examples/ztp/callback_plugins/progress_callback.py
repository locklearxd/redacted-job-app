import json # importing this here so that it is available to all methods in the class

from ansible.plugins.callback import CallbackBase #importing the base class for callbacks and Ansible modules

# defining a class that inherits from the base class and sets the callback version, type and name
class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'progress'

# initializing the class and setting the path to the files that will be used to store the results

    def __init__(self):
        super().__init__()
        self.success_file = '/var/www/html/ansible/success_file.json'
        self.error_file = '/var/www/html/ansible/error_file.json'
        self.progress_file = '/var/www/html/ansible/progress_file.json'
        self.debug_result_file = '/var/www/html/ansible/debug_result_file.json'
        self.current_progress = 0
        self.failed_tasks = []
        self.ok_tasks = []
        self.debug_result = []

# defining the collection of methods that will be used to capture the results of the playbook run

    def v2_playbook_on_task_start(self, task, is_conditional): #adds progress to the JSON file for each task that is started
        self.current_progress += 1
        self._write_progress()

    def v2_runner_on_ok(self, result, **kwargs): #adds progress to the JSON file for each task that is completed successfully
        self._write_progress()
        ok_host = result._host.get_name()
        ok_task = result.task_name
        ok_result = result._result
        self.ok_tasks.append({ok_task: ok_host})
        self._write_success()
        if result.task_name == "Gathering Facts":
            return    
        self.debug_result.append({ok_host: {ok_task: ok_result}})
        self._write_debug_result()

    def v2_runner_on_failed(self, result, **kwargs): #adds progress to the JSON file for each task that fails
        self._write_progress()

    def v2_runner_on_failed(self, result, ignore_errors=False): #adds debug results to the JSON file for each task that fails
        if result.task_name == "Gathering Facts":
            return    
        failed_host = result._host.get_name()
        failed_task = result.task_name
        failed_result = result._result
        self.debug_result.append({failed_host: {failed_task: failed_result}})
        self._write_debug_result()

    def v2_runner_on_failed(self, result, ignore_errors=False): #adds the host and task to the JSON file for each task that fails
        host = result._host.get_name()
        task = result.task_name
        self.failed_tasks.append({task: host})
        self._write_errors()

    def v2_runner_on_unreachable(self, result, **kwargs): #adds progress to the JSON file for each task that is unreachable
        self._write_progress()

    def v2_runner_on_unreachable(self, result, ignore_errors=False): #adds debug results to the JSON file for each task that is unreachable
        if result.task_name == "Gathering Facts":
            return
        unreachable_host = result._host.get_name()
        unreachable_task = result.task_name
        unreachable_result = result._result
        self.debug_result.append({unreachable_host: {unreachable_task: unreachable_result}})
        self._write_debug_result()

    def v2_playbook_on_stats(self, stats): #adds progress to the JSON file for each task that is completed
        self.current_progress = 100
        self._write_progress()

# defining the methods that will be used to write the results to the files in JSON to be parsed by the web interface consoles

    def _write_success(self):
        success_data = {
            'host_ok_task': self.ok_tasks
        }

        with open(self.success_file, 'w') as f:
            json.dump(success_data, f)

    def _write_errors(self):
        error_data = {
            'host_failed_task': self.failed_tasks
        }

        with open(self.error_file, 'w') as f:
            json.dump(error_data, f)

    def _write_debug_result(self):
        debug_data = {
            'host_debug_task': self.debug_result
        }

        with open(self.debug_result_file, 'w') as f:
            json.dump(debug_data, f)

    def _write_progress(self):
        progress_data = {
            'progress': self.current_progress,
            'completed': self.current_progress == 100
        }

        with open(self.progress_file, 'w') as f:
            json.dump(progress_data, f)