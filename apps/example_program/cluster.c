#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
 
typedef struct { double x, y; int group; } point_t, *point;
 
double randf(double m)
{
	return m * rand() / (RAND_MAX - 1.);
}
 
point gen_xy(int count, double radius)
{
	double ang, r;
	point p, pt = malloc(sizeof(point_t) * count);
 
	/* note: this is not a uniform 2-d distribution */
	for (p = pt + count; p-- > pt;) {
		ang = randf(2 * M_PI);
		r = randf(radius);
		p->x = r * cos(ang);
		p->y = r * sin(ang);
	}
 
	return pt;
}

point read_file(char* filename, int count)
{
    FILE *fp = fopen(filename, "r");
    if(fp == NULL) {
        printf("invalid file");
        exit(1);
    }
    point p, pt = malloc(sizeof(point_t) * count);
    p = pt;
    char line [128];
    int n = 0;
    while(fgets (line, sizeof line, fp) != NULL && n < count) {
        char* line_split = strtok(line, " \n");
        p->x = atoi(line_split);
        line_split = strtok(NULL, " \n");
        p->y = atoi(line_split);
        p++;
        n++;
    }
    return pt;
}
 
double dist2(point a, point b)
{
	double x = a->x - b->x, y = a->y - b->y;
	return x*x + y*y;
}

int nearest(point pt, point cent, int n_cluster, double *d2)
{
	int i, min_i;
	point c;
	double d, min_d;
 
#	define for_n for (c = cent, i = 0; i < n_cluster; i++, c++)
	for_n {
		min_d = HUGE_VAL;
		min_i = pt->group;
		for_n {
			if (min_d > (d = dist2(c, pt))) {
				min_d = d; min_i = i;
			}
		}
	}
	if (d2) *d2 = min_d;
	return min_i;
}
 
void kpp(point pts, int len, point cent, int n_cent)
{
#	define for_len for (j = 0, p = pts; j < len; j++, p++)
	int i, j;
	int n_cluster;
	double sum, *d = malloc(sizeof(double) * len);
 
	point p, c;
	cent[0] = pts[ rand() % len ];
	for (n_cluster = 1; n_cluster < n_cent; n_cluster++) {
		sum = 0;
		for_len {
			nearest(p, cent, n_cluster, d + j);
			sum += d[j];
		}
		sum = randf(sum);
		for_len {
			if ((sum -= d[j]) > 0) continue;
			cent[n_cluster] = pts[j];
			break;
		}
	}
	for_len p->group = nearest(p, cent, n_cluster, 0);
	free(d);
}
 
point lloyd(point pts, int len, int n_cluster)
{
	int i, j, min_i;
	int changed;
 
	point cent = malloc(sizeof(point_t) * n_cluster), p, c;
 
	/* assign init grouping randomly */
	//for_len p->group = j % n_cluster;
 
	/* or call k++ init */
	kpp(pts, len, cent, n_cluster);

    int count = 0;
 
	do {
		/* group element for centroids are used as counters */
		for_n { c->group = 0; c->x = c->y = 0; }
		for_len {
			c = cent + p->group;
			c->group++;
			c->x += p->x; c->y += p->y;
		}
		for_n { c->x /= c->group; c->y /= c->group; }
 
		changed = 0;
		/* find closest centroid of each point */
		for_len {
			min_i = nearest(p, cent, n_cluster, 0);
			if (min_i != p->group) {
				changed++;
				p->group = min_i;
			}
		}
        count++;
	} while (changed > (len >> 10)); /* stop when 99.9% of points are good */
 
	for_n { c->group = i; }
 
	return cent;
}
 
void print_eps(point pts, int len, point cent, int n_cluster, char* file)
{
    FILE *fp = fopen(file, "w");
#	define W 400
#	define H 400
	int i, j;
	point p, c;
	double min_x, max_x, min_y, max_y, scale, cx, cy;
	double *colors = malloc(sizeof(double) * n_cluster * 3);
 
	for_n {
		colors[3*i + 0] = (3 * (i + 1) % 11)/11.;
		colors[3*i + 1] = (7 * i % 11)/11.;
		colors[3*i + 2] = (9 * i % 11)/11.;
	}
 
	max_x = max_y = -(min_x = min_y = HUGE_VAL);
	for_len {
		if (max_x < p->x) max_x = p->x;
		if (min_x > p->x) min_x = p->x;
		if (max_y < p->y) max_y = p->y;
		if (min_y > p->y) min_y = p->y;
	}
	scale = W / (max_x - min_x);
	if (scale > H / (max_y - min_y)) scale = H / (max_y - min_y);
	cx = (max_x + min_x) / 2;
	cy = (max_y + min_y) / 2;
 
	fprintf(fp, "%%!PS-Adobe-3.0\n%%%%BoundingBox: -5 -5 %d %d\n", W + 10, H + 10);
	fprintf(fp, "/l {rlineto} def /m {rmoveto} def\n"
		"/c { .25 sub exch .25 sub exch .5 0 360 arc fill } def\n"
		"/s { moveto -2 0 m 2 2 l 2 -2 l -2 -2 l closepath "
		"	gsave 1 setgray fill grestore gsave 3 setlinewidth"
		" 1 setgray stroke grestore 0 setgray stroke }def\n"
	);
	for_n {
		fprintf(fp, "%g %g %g setrgbcolor\n",
			colors[3*i], colors[3*i + 1], colors[3*i + 2]);
		for_len {
			if (p->group != i) continue;
			fprintf(fp, "%.3f %.3f c\n",
				(p->x - cx) * scale + W / 2,
				(p->y - cy) * scale + H / 2);
		}
		fprintf(fp, "\n0 setgray %g %g s\n",
			(c->x - cx) * scale + W / 2,
			(c->y - cy) * scale + H / 2);
	}
	fprintf(fp, "\n%%%%EOF");
	free(colors);
    fclose(fp);
#	undef for_n
#	undef for_len
}
 
#define K 11
int main(int argc, char *argv[])
{
    char filename[30];
    char n_pts_[10];
    int n_pts;

    printf("Input file with points: ");
    fgets(filename, 30, stdin);
    char *pos;
    if((pos=strchr(filename, '\n')) != NULL) {
        *pos = '\0';
    }

    printf("Number of points to read: ");
    fgets(n_pts_, 10, stdin);
    n_pts = atoi(n_pts_);
    clock_t begin = clock();
    printf("Clustering...\n");
    int i;
    //point v = gen_xy(n_pts, 10);
    point v = read_file(filename, n_pts);
    point c = lloyd(v, n_pts, K);
    if(argc >= 3) {
        print_eps(v, n_pts, c, K, argv[2]);
    }
    // free(v); free(c);
    clock_t end = clock();
    printf("Clustering done: %f seconds \n", (double)(end - begin) / CLOCKS_PER_SEC);

	return 0;
}
