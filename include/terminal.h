#include "types.h"

#include <poll.h>

static int term_fds[4][2];
struct termios	orig_term;

static pthread_t term_poll_thread;

int read_in_full_terminal(int fd, void *buf, size_t count) {
	int total = 0;
	char *p = buf;

	while (count > 0) {
		int nr;

		nr = read(fd, p, count);
		if (nr <= 0) {
			if (total > 0)
				return total;

			return -1;
		}

		count -= nr;
		total += nr;
		p += nr;
	}

	return total;
}

int term_putc(char *addr, int cnt, int term) {
	int ret;
	int num_remaining = cnt;

	while (num_remaining) {
		ret = write(term_fds[term][1], addr, num_remaining);
		if (ret < 0)
			return cnt - num_remaining;
		num_remaining -= ret;
		addr += ret;
	}

	return cnt;
}

int term_getc(struct kvm *kvm, int term) {
	int term_got_escape = 0;
	unsigned char c;

	if (read_in_full_terminal(term_fds[term][0], &c, 1) < 0)
		return -1;

	if (term_got_escape) {
		term_got_escape = 0;
		if (c == 'x') {
			if (kvm->cpus[0] && kvm->cpus[0]->thread != 0)
				pthread_kill(kvm->cpus[0]->thread, SIGRTMIN);
		}
		if (c == 0x01)
			return c;
	}

	if (c == 0x01) {
		term_got_escape = 1;
		return -1;
	}

	return c;
}


void *term_poll_thread_loop(void *param)
{
	struct pollfd fds[4];
	struct kvm *kvm = (struct kvm *) param;
	int i;

	kvm__set_thread_name("term-poll");

	for (i = 0; i < 4; i++) {
		fds[i].fd = term_fds[i][0];
		fds[i].events = POLLIN;
		fds[i].revents = 0;
	}

	while (1) {
		/* Poll with infinite timeout */
		if(poll(fds, 4, -1) < 1)
			break;
		kvm__arch_read_term(kvm);
	}

	return NULL;
}

int term_readable(int term) {
	struct pollfd pollfd = (struct pollfd) {
		.fd	= term_fds[term][4],
		.events	= POLLIN,
		.revents = 0,
	};
	int err;

	err = poll(&pollfd, 1, 0);
	return (err > 0 && (pollfd.revents & POLLIN));
}

void term_cleanup(void) {
	for (int i = 0; i < 4; i++)
		tcsetattr(term_fds[i][0], TCSANOW, &orig_term);

}

void term_sig_cleanup(int sig) {

	
	signal(sig, SIG_DFL);
	raise(sig);
}