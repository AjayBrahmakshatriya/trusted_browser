#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

double randf(double m)
{
	return m * rand() / (RAND_MAX - 1.);
}

void gen_xy(FILE* fp, int count, double radius)
{
	double ang, r;
 
	/* note: this is not a uniform 2-d distribution */
	int i = 0;
    for (i = 0; i < count; i++) {
		ang = randf(2 * M_PI);
		r = randf(radius);
        fprintf(fp, "%f ", r*cos(ang));
        fprintf(fp, "%f\n", r*sin(ang));
	}
}

int main(int argc, char *argv[])
{
    char n_pts_[10];
    int n_pts;
    char filename[30];
    printf("Name of file to write to: ");
    fgets(filename, 30, stdin);
    printf("Number of points to write: ");
    fgets(n_pts_, 10, stdin);
    n_pts = atoi(n_pts_);

    FILE *fp = fopen(filename, "w");
    gen_xy(fp, n_pts, 10);
}
