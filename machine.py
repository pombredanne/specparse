# -*- coding: utf-8 -*-

from kobo.types import StateEnum, State



__all__ = ('FiniteMachine', 'State')


class MachineError(Exception):
    pass


class FiniteMachine(StateEnum):
    """
    Modified kobo.StateEnum to allow transition from current state
    to current_state.
    """
    def change_state(self, new_state, **kwargs):
        if new_state:
            new_state = self.get_item(new_state)
        if new_state is None:
            raise MachineError('New state attribute is required.')

        current_state = self._current_state.name
        next_states = [i[1] for i in
                       self.get_next_states_mapping(append_current=True)]
        if str(new_state) not in next_states:
            raise MachineError("Invalid transition '%s' -> '%s'." %
                               (current_state, new_state))

        # check transition permissions
        for func in self._current_state.check_perms:
            if not func(current_state, new_state, **kwargs):
                return False

        # run "leave" functions on current state
        for func in self._current_state.leave:
            func(current_state, new_state, **kwargs)

        # run "enter" functions on new state
        for func in new_state.enter:
            func(current_state, new_state, **kwargs)

        self.set_state(new_state)
        self._to = None
        return True
