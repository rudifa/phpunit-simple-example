<?php

use drmonkeyninja\Average;
use PHPUnit\Framework\TestCase;

class AverageTest extends TestCase
{
    protected $Average;

    public function setUp(): void
    {
        $this->Average = new Average();
    }

    public function testCalculationOfMean()
    {
        $numbers = [3, 7, 6, 1, 5];
        $this->assertEquals(4.4, $this->Average->mean($numbers));
    }

    public function testCalculationOfMedian()
    {
        $numbers = [3, 7, 6, 1, 5];
        $this->assertEquals(5, $this->Average->median($numbers));
    }

    // test mean, using a local instance of Average
    // test median, using a local instance of Average

    public function testMean() {
        $avg = new Average();
        $this->assertEquals(4.4, $avg->mean([3, 7, 6, 1, 5]));
    }
}
